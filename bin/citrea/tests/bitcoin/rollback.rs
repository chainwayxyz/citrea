use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::config::TestCaseConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use sov_ledger_rpc::LedgerRpcClient;

use super::{get_citrea_cli_path, get_citrea_path};

struct RollBackFullNodeSlots;

#[async_trait]
impl TestCase for RollBackFullNodeSlots {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_citrea_cli: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let citrea_cli = f.citrea_cli.as_ref().unwrap();

        sequencer.client.send_publish_batch_request().await?;

        let mined_blocks = 10;
        da.generate(mined_blocks).await?;

        let da_height = da.get_block_count().await?;
        assert_eq!(da_height, f.initial_da_height + mined_blocks);

        let finalized_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;

        let last_scanned_l1_height: u64 = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await
            .unwrap()
            .to();
        assert_eq!(last_scanned_l1_height, finalized_height);

        // Check that full node restarts from finalized_height
        full_node.wait_until_stopped().await?;
        full_node.start(None, None).await?;

        let last_scanned_l1_height: u64 = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await
            .unwrap()
            .to();
        assert_eq!(last_scanned_l1_height, finalized_height);

        // Rollback full node to initial_da_height
        full_node.wait_until_stopped().await?;

        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "full-node",
                    "--db-path",
                    full_node.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    "1",
                    "--l1-target",
                    &f.initial_da_height.to_string(),
                    "--sequencer-commitment-index",
                    "0",
                ],
            )
            .await?;

        full_node.start(None, None).await?;

        let last_scanned_l1_height: u64 = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await
            .unwrap()
            .to();
        assert_eq!(last_scanned_l1_height, f.initial_da_height);

        Ok(())
    }
}

#[tokio::test]
async fn test_rollback_fullnode_slots() -> Result<()> {
    TestCaseRunner::new(RollBackFullNodeSlots)
        .set_citrea_path(get_citrea_path())
        .set_citrea_cli_path(get_citrea_cli_path())
        .run()
        .await
}
