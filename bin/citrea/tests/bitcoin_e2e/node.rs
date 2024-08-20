use std::path::Path;
use std::time::Duration;

use tokio::process::Child;

use super::Result;

/// The Node trait defines the common interface shared between
/// BitcoinNode, Prover, Sequencer and FullNode
pub(crate) trait Node {
    type Config;

    /// Spawn a new node with specific config and return its child
    async fn spawn(test_config: &Self::Config, node_dir: &Path) -> Result<Child>;
    /// Stops the running node
    async fn stop(&mut self) -> Result<()>;
    /// Wait for the node to be reachable by its client.
    async fn wait_for_ready(&self, timeout: Duration) -> Result<()>;
}
