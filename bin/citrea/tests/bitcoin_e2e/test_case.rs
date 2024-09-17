//! This module provides the TestCaseRunner and TestCase trait for running and defining test cases.
//! It handles setup, execution, and cleanup of test environments.

use std::panic::{self};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use async_trait::async_trait;
use bitcoin_da::service::BitcoinServiceConfig;
use bitcoincore_rpc::RpcApi;
use citrea_sequencer::SequencerConfig;
use futures::FutureExt;
use sov_stf_runner::{ProverConfig, RpcConfig, RunnerConfig, StorageConfig};

use super::config::{
    default_rollup_config, BitcoinConfig, FullFullNodeConfig, FullProverConfig,
    FullSequencerConfig, RollupConfig, TestCaseConfig, TestCaseEnv, TestConfig,
};
use super::framework::TestFramework;
use super::node::NodeKind;
use super::utils::{copy_directory, get_available_port, get_tx_backup_dir};
use super::Result;
use crate::bitcoin_e2e::node::Node;
use crate::bitcoin_e2e::utils::{get_default_genesis_path, get_workspace_root};

// TestCaseRunner manages the lifecycle of a test case, including setup, execution, and cleanup.
/// It creates a test framework with the associated configs, spawns required nodes, connects them,
/// runs the test case, and performs cleanup afterwards. The `run` method handles any panics that
/// might occur during test execution and takes care of cleaning up and stopping the child processes.
pub struct TestCaseRunner<T: TestCase>(T);

impl<T: TestCase> TestCaseRunner<T> {
    /// Creates a new TestCaseRunner with the given test case.
    pub fn new(test_case: T) -> Self {
        Self(test_case)
    }

    pub async fn setup(&self, f: &mut TestFramework) -> Result<()> {
        let bitcoin_node = f.bitcoin_nodes.get(0).unwrap();
        let blocks_to_mature = 100;
        let blocks_to_fund = 25;
        if f.sequencer.is_some() {
            bitcoin_node
                .fund_wallet(NodeKind::Sequencer.to_string(), blocks_to_fund)
                .await?;
        }

        if f.prover.is_some() {
            bitcoin_node
                .fund_wallet(NodeKind::Prover.to_string(), blocks_to_fund)
                .await?;
        }

        bitcoin_node.generate(blocks_to_mature, None).await?;

        f.initial_da_height = bitcoin_node.get_block_count().await?;
        Ok(())
    }

    /// Internal method to set up connect the nodes, wait for the nodes to be ready and run the test.
    async fn run_test_case(&mut self, f: &mut TestFramework) -> Result<()> {
        f.bitcoin_nodes.connect_nodes().await?;

        if let Some(sequencer) = &f.sequencer {
            sequencer.wait_for_ready(Duration::from_secs(5)).await?;
        }

        self.0.run_test(f).await
    }

    /// Executes the test case, handling any panics and performing cleanup.
    ///
    /// This sets up the framework, executes the test, and ensures cleanup is performed even if a panic occurs.
    pub async fn run(mut self) -> Result<()> {
        let result = panic::AssertUnwindSafe(async {
            let mut framework = TestFramework::new(Self::generate_test_config()?).await?;
            self.setup(&mut framework).await?;

            let test_result = self.run_test_case(&mut framework).await;

            if test_result.is_err() {
                if let Err(e) = framework.dump_log() {
                    eprintln!("Error dumping log: {}", e);
                }
            }

            framework.stop().await?;

            test_result
        })
        .catch_unwind()
        .await;

        // Additional test cleanup
        self.0.cleanup().await?;

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(panic_error) => {
                let panic_msg = panic_error
                    .downcast_ref::<String>()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown panic".to_string());
                bail!(panic_msg)
            }
        }
    }

    fn generate_test_config() -> Result<TestConfig> {
        let test_case = T::test_config();
        let env = T::test_env();
        let bitcoin = T::bitcoin_config();
        let prover = T::prover_config();
        let sequencer = T::sequencer_config();
        let sequencer_rollup = default_rollup_config();
        let prover_rollup = default_rollup_config();
        let full_node_rollup = default_rollup_config();

        let [bitcoin_dir, dbs_dir, prover_dir, sequencer_dir, full_node_dir, genesis_dir] =
            create_dirs(&test_case.dir)?;

        copy_genesis_dir(&test_case.genesis_dir, &genesis_dir)?;

        let mut bitcoin_confs = vec![];
        for i in 0..test_case.num_nodes {
            let data_dir = bitcoin_dir.join(i.to_string());
            std::fs::create_dir_all(&data_dir)
                .with_context(|| format!("Failed to create {} directory", data_dir.display()))?;

            let p2p_port = get_available_port()?;
            let rpc_port = get_available_port()?;

            bitcoin_confs.push(BitcoinConfig {
                p2p_port,
                rpc_port,
                data_dir,
                env: env.bitcoin().clone(),
                ..bitcoin.clone()
            })
        }

        // Target first bitcoin node as DA for now
        let da_config: BitcoinServiceConfig = bitcoin_confs[0].clone().into();

        let sequencer_rollup = {
            let bind_port = get_available_port()?;
            let node_kind = NodeKind::Sequencer.to_string();
            RollupConfig {
                da: BitcoinServiceConfig {
                    da_private_key: Some(
                        "045FFC81A3C1FDB3AF1359DBF2D114B0B3EFBF7F29CC9C5DA01267AA39D2C78D"
                            .to_string(),
                    ),
                    node_url: format!("{}/wallet/{}", da_config.node_url, node_kind),
                    tx_backup_dir: get_tx_backup_dir(),
                    ..da_config.clone()
                },
                storage: StorageConfig {
                    path: dbs_dir.join(format!("{}-db", node_kind)),
                    db_max_open_files: None,
                },
                rpc: RpcConfig {
                    bind_port,
                    ..sequencer_rollup.rpc
                },
                ..sequencer_rollup
            }
        };

        let runner_config = Some(RunnerConfig {
            sequencer_client_url: format!(
                "http://{}:{}",
                sequencer_rollup.rpc.bind_host, sequencer_rollup.rpc.bind_port,
            ),
            include_tx_body: true,
            accept_public_input_as_proven: Some(true),
            sync_blocks_count: Default::default(),
        });

        let prover_rollup = {
            let bind_port = get_available_port()?;
            let node_kind = NodeKind::Prover.to_string();
            RollupConfig {
                da: BitcoinServiceConfig {
                    da_private_key: Some(
                        "75BAF964D074594600366E5B111A1DA8F86B2EFE2D22DA51C8D82126A0FCAC72"
                            .to_string(),
                    ),
                    node_url: format!("{}/wallet/{}", da_config.node_url, node_kind),
                    tx_backup_dir: get_tx_backup_dir(),
                    ..da_config.clone()
                },
                storage: StorageConfig {
                    path: dbs_dir.join(format!("{}-db", node_kind)),
                    db_max_open_files: None,
                },
                rpc: RpcConfig {
                    bind_port,
                    ..prover_rollup.rpc
                },
                runner: runner_config.clone(),
                ..prover_rollup
            }
        };

        let full_node_rollup = {
            let bind_port = get_available_port()?;
            let node_kind = NodeKind::FullNode.to_string();
            RollupConfig {
                da: BitcoinServiceConfig {
                    node_url: format!(
                        "{}/wallet/{}",
                        da_config.node_url,
                        NodeKind::Bitcoin // Use default wallet
                    ),
                    tx_backup_dir: get_tx_backup_dir(),
                    ..da_config.clone()
                },
                storage: StorageConfig {
                    path: dbs_dir.join(format!("{}-db", node_kind)),
                    db_max_open_files: None,
                },
                rpc: RpcConfig {
                    bind_port,
                    ..full_node_rollup.rpc
                },
                runner: runner_config.clone(),
                ..full_node_rollup
            }
        };

        Ok(TestConfig {
            bitcoin: bitcoin_confs,
            sequencer: FullSequencerConfig {
                rollup: sequencer_rollup,
                dir: sequencer_dir,
                docker_image: None,
                node: sequencer,
                env: env.sequencer(),
            },
            prover: FullProverConfig {
                rollup: prover_rollup,
                dir: prover_dir,
                docker_image: None,
                node: prover,
                env: env.prover(),
            },
            full_node: FullFullNodeConfig {
                rollup: full_node_rollup,
                dir: full_node_dir,
                docker_image: None,
                node: (),
                env: env.full_node(),
            },
            test_case,
        })
    }
}

/// Defines the interface for implementing test cases.
///
/// This trait should be implemented by every test case to define the configuration
/// and inner test logic. It provides default configurations that should be sane for most test cases,
/// which can be overridden by implementing the associated methods.
#[async_trait]
pub trait TestCase: Send + Sync + 'static {
    /// Returns the test case configuration.
    /// Override this method to provide custom test configurations.
    fn test_config() -> TestCaseConfig {
        TestCaseConfig::default()
    }

    /// Returns the test case env.
    /// Override this method to provide custom env per node.
    fn test_env() -> TestCaseEnv {
        TestCaseEnv::default()
    }

    /// Returns the Bitcoin configuration for the test.
    /// Override this method to provide a custom Bitcoin configuration.
    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig::default()
    }

    /// Returns the sequencer configuration for the test.
    /// Override this method to provide a custom sequencer configuration.
    fn sequencer_config() -> SequencerConfig {
        SequencerConfig::default()
    }

    /// Returns the prover configuration for the test.
    /// Override this method to provide a custom prover configuration.
    fn prover_config() -> ProverConfig {
        ProverConfig::default()
    }

    /// Implements the actual test logic.
    ///
    /// This method is where the test case should be implemented. It receives
    /// a reference to the TestFramework, which provides access to the test environment.
    ///
    /// # Arguments
    /// * `framework` - A reference to the TestFramework instance
    async fn run_test(&mut self, framework: &TestFramework) -> Result<()>;

    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }
}

fn create_dirs(base_dir: &Path) -> Result<[PathBuf; 6]> {
    let paths = [
        NodeKind::Bitcoin.to_string(),
        "dbs".to_string(),
        NodeKind::Prover.to_string(),
        NodeKind::Sequencer.to_string(),
        NodeKind::FullNode.to_string(),
        "genesis".to_string(),
    ]
    .map(|dir| base_dir.join(dir));

    for path in &paths {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Failed to create {} directory", path.display()))?;
    }

    Ok(paths)
}

fn copy_genesis_dir(genesis_dir: &Option<String>, target_dir: &Path) -> std::io::Result<()> {
    let genesis_dir =
        genesis_dir
            .as_ref()
            .map(PathBuf::from)
            .map_or_else(get_default_genesis_path, |dir| {
                if dir.is_absolute() {
                    dir
                } else {
                    get_workspace_root().join(dir)
                }
            });

    copy_directory(genesis_dir, target_dir)
}
