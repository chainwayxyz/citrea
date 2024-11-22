mod test_utils;

use async_trait::async_trait;
use citrea_common::tasks::manager::TaskManager;
use citrea_e2e::config::TestCaseConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use test_utils::{generate_mock_txs, get_citrea_path, get_service};

struct BitcoinVerifierTest;

#[async_trait]
impl TestCase for BitcoinVerifierTest {
    fn test_config() -> TestCaseConfig {
        // Only run bitcoin regtest
        TestCaseConfig {
            with_sequencer: false,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let mut task_manager = TaskManager::default();
        let da = f.bitcoin_nodes.get(0).unwrap();

        let da_service = get_service(&mut task_manager, &da.config).await;
        generate_mock_txs(&da_service).await;

        task_manager.abort().await;
        Ok(())
    }
}

#[cfg(feature = "native")]
#[tokio::test]
async fn test_bitcoin_verifier() -> Result<()> {
    TestCaseRunner::new(BitcoinVerifierTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
