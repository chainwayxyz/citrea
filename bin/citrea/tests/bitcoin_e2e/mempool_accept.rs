use async_trait::async_trait;
use bitcoin_da::service::FINALITY_DEPTH;
use bitcoincore_rpc::RpcApi;

use citrea_e2e::config::BitcoinConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::L2Node;
use citrea_e2e::Result;

struct MempoolAcceptTest;

#[async_trait]
impl TestCase for MempoolAcceptTest {
    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec![
                // Restrictive mempool policy
                "-limitancestorcount=0",
                "-limitancestorsize=0",
            ],
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");

        let min_soft_conf_per_commitment = sequencer.min_soft_confirmations_per_commitment();

        // publish min_soft_conf_per_commitment - 1 confirmations, no commitments should be sent
        for _ in 0..min_soft_conf_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(min_soft_conf_per_commitment, None)
            .await;

        da.generate(FINALITY_DEPTH).await?;

        // TODO find the right assertions here
        // Should be either 2 or 0
        // Before this PR and the addition of testmempoolaccept, first tx would go in and second would be rejected due to mempool policy set above

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        Ok(())
    }
}

#[tokio::test]
async fn test_mempool_accept() -> Result<()> {
    TestCaseRunner::new(MempoolAcceptTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
