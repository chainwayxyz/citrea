use std::time::Duration;

use anyhow::bail;
use async_trait::async_trait;
use bitcoincore_rpc::json::IndexStatus;
use bitcoincore_rpc::RpcApi;

use crate::bitcoin_e2e::config::{BitcoinConfig, TestCaseConfig};
use crate::bitcoin_e2e::framework::TestFramework;
use crate::bitcoin_e2e::node::Restart;
use crate::bitcoin_e2e::test_case::{TestCase, TestCaseRunner};
use crate::bitcoin_e2e::Result;

struct BasicSyncTest;

#[async_trait]
impl TestCase for BasicSyncTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: false,
            n_nodes: 2,
            timeout: Duration::from_secs(60),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
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

struct RestartBitcoinTest;

#[async_trait]
impl TestCase for RestartBitcoinTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: false,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-txindex=0"],
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        // Add txindex flag to check that restart takes into account the extra args
        let new_conf = BitcoinConfig {
            extra_args: vec!["-txindex=1"],
            ..da.config.clone()
        };

        let block_before = da.get_block_count().await?;
        let info = da.get_index_info().await?;

        assert_eq!(info.txindex, None);

        // Restart node with txindex
        da.restart(Some(new_conf)).await?;

        let block_after = da.get_block_count().await?;
        let info = da.get_index_info().await?;

        assert!(matches!(
            info.txindex,
            Some(IndexStatus { synced: true, .. })
        ));
        // Assert that state is kept between restarts
        assert_eq!(block_before, block_after);

        Ok(())
    }
}

#[tokio::test]
async fn test_basic_sync() -> Result<()> {
    TestCaseRunner::new(BasicSyncTest).run().await
}

#[tokio::test]
async fn test_restart_bitcoin() -> Result<()> {
    TestCaseRunner::new(RestartBitcoinTest).run().await
}
