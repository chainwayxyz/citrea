use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use bollard::container::StopContainerOptions;
use bollard::Docker;
use tokio::process::Child;

use super::Result;
use crate::test_client::TestClient;
use crate::test_helpers::wait_for_l2_block;

#[derive(Debug)]
pub enum NodeKind {
    Bitcoin,
    Prover,
    Sequencer,
    FullNode,
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeKind::Bitcoin => write!(f, "bitcoin"),
            NodeKind::Prover => write!(f, "prover"),
            NodeKind::Sequencer => write!(f, "sequencer"),
            NodeKind::FullNode => write!(f, "full-node"),
        }
    }
}

#[derive(Debug)]
pub struct ContainerSpawnOutput {
    pub id: String,
    pub ip: String,
}

#[derive(Debug)]
pub enum SpawnOutput {
    Child(Child),
    Container(ContainerSpawnOutput),
}
/// The Node trait defines the common interface shared between
/// BitcoinNode, Prover, Sequencer and FullNode
pub(crate) trait Node {
    type Config;
    type Client;

    /// Spawn a new node with specific config and return its child
    fn spawn(test_config: &Self::Config) -> Result<SpawnOutput>;
    fn spawn_output(&mut self) -> &mut SpawnOutput;

    /// Stops the running node
    async fn stop(&mut self) -> Result<()> {
        match self.spawn_output() {
            SpawnOutput::Child(process) => {
                process
                    .kill()
                    .await
                    .context("Failed to kill child process")?;
                Ok(())
            }
            SpawnOutput::Container(ContainerSpawnOutput { id, .. }) => {
                println!("Removing container {id}");
                let docker =
                    Docker::connect_with_local_defaults().context("Failed to connect to Docker")?;
                docker
                    .stop_container(id, Some(StopContainerOptions { t: 10 }))
                    .await
                    .context("Failed to stop Docker container")?;
                docker
                    .remove_container(id, None)
                    .await
                    .context("Failed to remove Docker container")?;
                Ok(())
            }
        }
    }

    /// Wait for the node to be reachable by its client.
    async fn wait_for_ready(&self, timeout: Duration) -> Result<()>;

    fn client(&self) -> &Self::Client;

    #[allow(unused)]
    fn env(&self) -> Vec<(&'static str, &'static str)> {
        Vec::new()
    }
}

pub trait L2Node: Node<Client = TestClient> {
    async fn wait_for_l2_height(&self, height: u64, timeout: Option<Duration>) {
        wait_for_l2_block(self.client(), height, timeout).await
    }
}

pub trait LogProvider: Node {
    fn kind(&self) -> NodeKind;
    fn log_path(&self) -> PathBuf;
    fn as_erased(&self) -> &dyn LogProviderErased
    where
        Self: Sized,
    {
        self
    }
}

pub trait LogProviderErased {
    fn kind(&self) -> NodeKind;
    fn log_path(&self) -> PathBuf;
}

impl<T: LogProvider> LogProviderErased for T {
    fn kind(&self) -> NodeKind {
        LogProvider::kind(self)
    }

    fn log_path(&self) -> PathBuf {
        LogProvider::log_path(self)
    }
}
