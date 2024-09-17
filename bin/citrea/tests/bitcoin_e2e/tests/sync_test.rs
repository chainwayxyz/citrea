use std::time::Duration;

use anyhow::bail;
use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;

use crate::bitcoin_e2e::config::TestCaseConfig;
use crate::bitcoin_e2e::framework::TestFramework;
use crate::bitcoin_e2e::test_case::{TestCase, TestCaseRunner};
use crate::bitcoin_e2e::Result;

struct BasicSyncTest;

#[async_trait]
impl TestCase for BasicSyncTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            num_nodes: 2,
            timeout: Duration::from_secs(60),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &TestFramework) -> Result<()> {
        let (Some(da0), Some(da1)) = (f.bitcoin_nodes.get(0), f.bitcoin_nodes.get(1)) else {
            bail!("bitcoind not running. Test should run with two da nodes")
        };
        let initial_height = f.initial_da_height;

        // Generate some blocks on node0
        da0.generate(5, None).await?;

        let height0 = da0.get_block_count().await?;
        let height1 = da1.get_block_count().await?;

        // Nodes are now out of sync
        assert_eq!(height0, initial_height + 5);
        assert_eq!(height1, 0);

        // Sync both nodes
        f.bitcoin_nodes
            .wait_for_sync(Duration::from_secs(30))
            .await?;

        let height0 = da0.get_block_count().await?;
        let height1 = da1.get_block_count().await?;

        // Assert that nodes are in sync
        assert_eq!(height0, height1, "Block heights don't match");
        Ok(())
    }
}

#[tokio::test]
async fn basic_sync_test() -> Result<()> {
    TestCaseRunner::new(BasicSyncTest).run().await
}
