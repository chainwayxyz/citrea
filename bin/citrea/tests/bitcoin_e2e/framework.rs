use std::future::Future;

use super::bitcoin::BitcoinNodeCluster;
use super::config::TestConfig;
use super::docker::DockerEnv;
use super::full_node::FullNode;
use super::node::Node;
use super::sequencer::Sequencer;
use super::Result;
use crate::bitcoin_e2e::prover::Prover;
use crate::bitcoin_e2e::utils::get_stdout_path;

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

    pub async fn stop(&mut self) -> Result<()> {
        println!("Stopping framework...");

        if let Some(docker) = &self.ctx.docker {
            let _ = docker.cleanup().await;
            println!("Successfully cleaned docker");
        }

        let _ = self.bitcoin_nodes.stop_all().await;
        println!("Successfully stopped bitcoin nodes");

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
                    get_stdout_path(sequencer.dir()).display()
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
