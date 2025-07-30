use std::net::SocketAddr;

use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{ListenModeConfig, SequencerConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::NodeKind;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use citrea_evm::system_contracts::BitcoinLightClient;
use citrea_evm::BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS;
use sha2::digest::generic_array::sequence;
use sov_ledger_rpc::LedgerRpcClient;

use super::get_citrea_path;
use crate::common::make_test_client;

struct ReadOnlySequencerTest;

#[async_trait]
impl TestCase for ReadOnlySequencerTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            n_nodes: std::collections::HashMap::from([(NodeKind::Sequencer, 2)]),
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

        let sequ_config = readonly_sequencer.config.clone();

        let mut read_only_node_config = sequ_config;

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
