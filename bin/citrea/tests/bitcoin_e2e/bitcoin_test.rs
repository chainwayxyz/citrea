use async_trait::async_trait;
use bitcoincore_rpc::json::IndexStatus;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::config::{BitcoinConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;

use super::get_citrea_path;

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
async fn test_restart_bitcoin() -> Result<()> {
    TestCaseRunner::new(RestartBitcoinTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
