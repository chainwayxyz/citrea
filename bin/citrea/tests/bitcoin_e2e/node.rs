use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use bollard::container::StopContainerOptions;
use bollard::Docker;
use tokio::process::Child;

use super::Result;

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

    /// Spawn a new node with specific config and return its child
    async fn spawn(test_config: &Self::Config, node_dir: &Path) -> Result<SpawnOutput>;
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
}
