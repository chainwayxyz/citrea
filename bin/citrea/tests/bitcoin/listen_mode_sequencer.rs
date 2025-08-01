use std::collections::HashMap;

use async_trait::async_trait;
use citrea_e2e::config::{ListenModeConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::NodeKind;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;

use super::get_citrea_path;

struct ReadOnlySequencerTest;

#[async_trait]
impl TestCase for ReadOnlySequencerTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            n_nodes: HashMap::from([(NodeKind::Sequencer, 2)]),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let Some(cluster) = f.sequencer_cluster.take() else {
            anyhow::bail!("Sequencer cluster not running. Set n_nodes with Sequencer to 2 or more")
        };

        let (cluster, node) = cluster.take(1);

        let Some(sequencer) = cluster.get(0) else {
            anyhow::bail!("Sequencer not found in sequencer cluster. Set n_nodes with Sequencer")
        };

        let sequencer_rpc_url = format!(
            "http://{}:{}",
            sequencer.config.clone().rollup.rpc.bind_host,
            sequencer.config.clone().rollup.rpc.bind_port
        );

        let mut readonly_sequencer = node.unwrap();

        let seq_config = readonly_sequencer.config.clone();

        let mut read_only_node_config = seq_config;

        read_only_node_config.node.listen_mode_config = Some(ListenModeConfig {
            sequencer_client_url: sequencer_rpc_url,
            sync_blocks_count: 10,
        });

        readonly_sequencer
            .restart(Some(read_only_node_config), None)
            .await?;

        for _ in 0..5 {
            sequencer.client.send_publish_batch_request().await?;
        }

        readonly_sequencer.wait_for_l2_height(5, None).await?;

        Ok(())
    }
}

#[tokio::test]
async fn read_only_sequencer_test() -> Result<()> {
    TestCaseRunner::new(ReadOnlySequencerTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
