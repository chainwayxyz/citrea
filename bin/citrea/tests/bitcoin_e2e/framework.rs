use std::path::{Path, PathBuf};

use anyhow::Context;
use bitcoin_da::service::DaServiceConfig;
use sov_stf_runner::{RpcConfig, RunnerConfig, StorageConfig};

use super::bitcoin::BitcoinNodeCluster;
use super::config::BitcoinConfig;
use super::config::RollupConfig;
use super::config::TestConfig;
use super::docker::DockerEnv;
use super::full_node::FullNode;
use super::node::Node;
use super::sequencer::Sequencer;
use super::{get_available_port, Result};
use crate::bitcoin_e2e::prover::Prover;
use crate::bitcoin_e2e::utils::get_stdout_path;
use std::future::Future;

pub struct TestContext {
    pub config: TestConfig,
    pub docker: Option<DockerEnv>,
}

pub struct TestFramework {
    ctx: TestContext,
    pub bitcoin_nodes: BitcoinNodeCluster,
    pub sequencer: Option<Sequencer>,
    pub prover: Option<Prover>,
    pub full_node: Option<FullNode>,
    show_logs: bool,
}

async fn create_optional<T>(pred: bool, f: impl Future<Output = Result<T>>) -> Result<Option<T>> {
    if pred {
        Ok(Some(f.await?))
    } else {
        Ok(None)
    }
}

impl TestFramework {
    pub async fn new(base_conf: TestConfig) -> Result<Self> {
        anyhow::ensure!(
            base_conf.test_case.num_nodes > 0,
            "At least one bitcoin node has to be running"
        );

        let config = Self::generate_test_config(base_conf)?;

        let docker = if config.test_case.docker {
            Some(DockerEnv::new().await?)
        } else {
            None
        };

        let ctx = TestContext { config, docker };

        let bitcoin_nodes = BitcoinNodeCluster::new(&ctx).await?;
        let sequencer =
            create_optional(ctx.config.test_case.with_sequencer, Sequencer::new(&ctx)).await?;

        let (prover, full_node) = tokio::try_join!(
            create_optional(ctx.config.test_case.with_prover, Prover::new(&ctx)),
            create_optional(ctx.config.test_case.with_full_node, FullNode::new(&ctx)),
        )?;

        Ok(Self {
            bitcoin_nodes,
            sequencer,
            prover,
            full_node,
            ctx,
            show_logs: true,
        })
    }

    fn generate_test_config(base_conf: TestConfig) -> Result<TestConfig> {
        let (bitcoin_dir, dbs_dir) = create_dirs(&base_conf.test_case.dir)?;

        let mut bitcoin_confs = vec![];
        for i in 0..base_conf.test_case.num_nodes {
            let data_dir = bitcoin_dir.join(i.to_string());
            std::fs::create_dir_all(&data_dir)
                .with_context(|| format!("Failed to create {} directory", data_dir.display()))?;

            let p2p_port = get_available_port()?;
            let rpc_port = get_available_port()?;

            bitcoin_confs.push(BitcoinConfig {
                p2p_port,
                rpc_port,
                data_dir,
                ..base_conf.bitcoin[0].clone()
            })
        }

        // Target first bitcoin node as DA for now
        let da_config: DaServiceConfig = bitcoin_confs[0].clone().into();

        let sequencer_rollup = {
            let bind_port = get_available_port()?;
            RollupConfig {
                da: da_config.clone(),
                storage: StorageConfig {
                    path: dbs_dir.join("sequencer-db"),
                },
                rpc: RpcConfig {
                    bind_port,
                    ..base_conf.sequencer_rollup.rpc
                },
                ..base_conf.sequencer_rollup
            }
        };

        let runner_config = Some(RunnerConfig {
            sequencer_client_url: format!(
                "http://{}:{}",
                sequencer_rollup.rpc.bind_host, sequencer_rollup.rpc.bind_port
            ),
            include_tx_body: true,
            accept_public_input_as_proven: None,
        });

        let prover_rollup = {
            let bind_port = get_available_port()?;
            RollupConfig {
                da: da_config.clone(),
                storage: StorageConfig {
                    path: dbs_dir.join("prover-db"),
                },
                rpc: RpcConfig {
                    bind_port,
                    ..base_conf.prover_rollup.rpc
                },
                runner: runner_config.clone(),
                ..base_conf.prover_rollup
            }
        };

        let full_node_rollup = {
            let bind_port = get_available_port()?;
            RollupConfig {
                da: da_config.clone(),
                storage: StorageConfig {
                    path: dbs_dir.join("full-node-db"),
                },
                rpc: RpcConfig {
                    bind_port,
                    ..base_conf.full_node_rollup.rpc
                },
                runner: runner_config.clone(),
                ..base_conf.full_node_rollup
            }
        };

        Ok(TestConfig {
            bitcoin: bitcoin_confs,
            sequencer_rollup,
            prover_rollup,
            full_node_rollup,
            ..base_conf
        })
    }

    pub async fn stop(&mut self) -> Result<()> {
        println!("Stopping framework...");
        self.bitcoin_nodes.stop_all().await?;

        println!("Successfully stopped bitcoin nodes");

        if let Some(sequencer) = &mut self.sequencer {
            sequencer.stop().await?;
            println!("Successfully stopped sequencer");
        }

        if let Some(prover) = &mut self.prover {
            prover.stop().await?;
            println!("Successfully stopped prover");
        }

        if let Some(full_node) = &mut self.full_node {
            full_node.stop().await?;
            println!("Successfully stopped full_node");
        }

        if let Some(docker) = &self.ctx.docker {
            docker.cleanup().await?;
            println!("Successfully cleaned docker");
        }

        if self.show_logs {
            println!(
                "Logs available at {}",
                self.ctx.config.test_case.dir.display()
            );

            if let Some(bitcoin_node) = self.bitcoin_nodes.get(0) {
                println!(
                    "Bitcoin logs available at : {}",
                    bitcoin_node.get_log_path().display()
                );
            }

            if let Some(sequencer) = &self.sequencer {
                println!(
                    "Sequencer logs available at {}",
                    get_stdout_path(&sequencer.dir).display()
                );
            }

            if let Some(full_node) = &self.full_node {
                println!(
                    "Full node logs available at {}",
                    get_stdout_path(&full_node.dir).display()
                );
            }

            if let Some(prover) = &self.prover {
                println!(
                    "Prover logs available at {}",
                    get_stdout_path(&prover.dir).display()
                );
            }
        }

        Ok(())
    }
}

fn create_dirs(base_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let directories = ["bitcoin", "dbs", "prover", "sequencer", "full-node"];

    for dir in &directories {
        std::fs::create_dir_all(base_dir.join(dir))
            .with_context(|| format!("Failed to create {} directory", dir))?;
    }

    Ok((base_dir.join("bitcoin"), base_dir.join("dbs")))
}
