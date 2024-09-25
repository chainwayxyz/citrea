use std::future::Future;
use std::sync::Arc;

use bitcoincore_rpc::RpcApi;

use super::bitcoin::BitcoinNodeCluster;
use super::config::TestConfig;
use super::docker::DockerEnv;
use super::full_node::FullNode;
use super::node::{LogProvider, LogProviderErased, Node, NodeKind};
use super::sequencer::Sequencer;
use super::Result;
use crate::bitcoin_e2e::prover::Prover;
use crate::bitcoin_e2e::utils::tail_file;

pub struct TestContext {
    pub config: TestConfig,
    pub docker: Arc<Option<DockerEnv>>,
}

impl TestContext {
    fn new(config: TestConfig, docker: Option<DockerEnv>) -> Self {
        Self {
            config,
            docker: Arc::new(docker),
        }
    }
}

pub struct TestFramework {
    ctx: TestContext,
    pub bitcoin_nodes: BitcoinNodeCluster,
    pub sequencer: Option<Sequencer>,
    pub prover: Option<Prover>,
    pub full_node: Option<FullNode>,
    show_logs: bool,
    pub initial_da_height: u64,
}

async fn create_optional<T>(pred: bool, f: impl Future<Output = Result<T>>) -> Result<Option<T>> {
    if pred {
        Ok(Some(f.await?))
    } else {
        Ok(None)
    }
}

impl TestFramework {
    pub async fn new(config: TestConfig) -> Result<Self> {
        anyhow::ensure!(
            config.test_case.num_nodes > 0,
            "At least one bitcoin node has to be running"
        );

        let docker = if config.test_case.docker {
            Some(DockerEnv::new().await?)
        } else {
            None
        };

        let ctx = TestContext::new(config, docker);

        let bitcoin_nodes = BitcoinNodeCluster::new(&ctx).await?;

        // tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        Ok(Self {
            bitcoin_nodes,
            sequencer: None,
            prover: None,
            full_node: None,
            ctx,
            show_logs: true,
            initial_da_height: 0,
        })
    }

    pub async fn init_nodes(&mut self) -> Result<()> {
        // Has to initialize sequencer first since prover and full node depend on it
        self.sequencer = create_optional(
            self.ctx.config.test_case.with_sequencer,
            Sequencer::new(&self.ctx),
        )
        .await?;

        (self.prover, self.full_node) = tokio::try_join!(
            create_optional(
                self.ctx.config.test_case.with_prover,
                Prover::new(&self.ctx)
            ),
            create_optional(
                self.ctx.config.test_case.with_full_node,
                FullNode::new(&self.ctx)
            ),
        )?;

        Ok(())
    }

    fn get_nodes_as_log_provider(&self) -> Vec<&dyn LogProviderErased> {
        vec![
            self.bitcoin_nodes.get(0).map(LogProvider::as_erased),
            self.sequencer.as_ref().map(LogProvider::as_erased),
            self.full_node.as_ref().map(LogProvider::as_erased),
            self.prover.as_ref().map(LogProvider::as_erased),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    pub fn show_log_paths(&self) {
        if self.show_logs {
            println!(
                "Logs available at {}",
                self.ctx.config.test_case.dir.display()
            );

            for node in self.get_nodes_as_log_provider() {
                println!(
                    "{} logs available at : {}",
                    node.kind(),
                    node.log_path().display()
                );
            }
        }
    }

    pub fn dump_log(&self) -> Result<()> {
        println!("Dumping logs:");

        for node in self.get_nodes_as_log_provider() {
            println!("{} logs (last 25 lines):", node.kind());
            if let Err(e) = tail_file(&node.log_path(), 300) {
                eprint!("{e}");
            }
        }
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        println!("Stopping framework...");

        if let Some(sequencer) = &mut self.sequencer {
            let _ = sequencer.stop().await;
            println!("Successfully stopped sequencer");
        }

        if let Some(prover) = &mut self.prover {
            let _ = prover.stop().await;
            println!("Successfully stopped prover");
        }

        if let Some(full_node) = &mut self.full_node {
            let _ = full_node.stop().await;
            println!("Successfully stopped full_node");
        }

        let _ = self.bitcoin_nodes.stop_all().await;
        println!("Successfully stopped bitcoin nodes");

        if let Some(docker) = self.ctx.docker.as_ref() {
            let _ = docker.cleanup().await;
            println!("Successfully cleaned docker");
        }

        Ok(())
    }

    pub async fn fund_da_wallets(&mut self) -> Result<()> {
        let da = self.bitcoin_nodes.get(0).unwrap();

        da.create_wallet(&NodeKind::Sequencer.to_string(), None, None, None, None)
            .await?;
        da.create_wallet(&NodeKind::Prover.to_string(), None, None, None, None)
            .await?;
        da.create_wallet(&NodeKind::Bitcoin.to_string(), None, None, None, None)
            .await?;

        let blocks_to_mature = 100;
        let blocks_to_fund = 25;
        if self.ctx.config.test_case.with_sequencer {
            da.fund_wallet(NodeKind::Sequencer.to_string(), blocks_to_fund)
                .await?;
        }

        if self.ctx.config.test_case.with_prover {
            da.fund_wallet(NodeKind::Prover.to_string(), blocks_to_fund)
                .await?;
        }

        da.generate(blocks_to_mature, None).await?;
        self.initial_da_height = da.get_block_count().await?;
        Ok(())
    }
}
