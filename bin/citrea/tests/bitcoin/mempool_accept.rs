use std::time::Duration;

use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::{BitcoinNode, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::config::BitcoinConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;

use super::get_citrea_path;

const MEMPOOL_SETTLE_TIMEOUT: Duration = Duration::from_secs(10);

async fn observe_commit_reveal_mempool_len(da: &BitcoinNode) -> Result<usize> {
    let _ = da.wait_mempool_len(2, Some(MEMPOOL_SETTLE_TIMEOUT)).await;
    Ok(da.get_raw_mempool().await?.len())
}

fn assert_atomic_commit_reveal_result(mempool_len: usize, context: &str) {
    assert!(
        matches!(mempool_len, 0 | 2),
        "{context}: expected the commit/reveal pair to be either fully queued or fully broadcast, found {mempool_len} txs in the mempool",
    );
}

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

        let min_l2_block_per_commitment = sequencer.config.node.max_l2_blocks_per_commitment;

        // publish min_l2_block_per_commitment - 1 confirmations, no commitments should be sent
        for _ in 0..min_l2_block_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(min_l2_block_per_commitment, None)
            .await;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Under restrictive ancestor policy, the commit/reveal pair must never be partially
        // broadcast. It can either stay queued (0 txs) or reach the mempool atomically (2 txs).
        let mempool_len = observe_commit_reveal_mempool_len(da).await?;
        assert_atomic_commit_reveal_result(mempool_len, "after triggering sequencer commitments");

        if mempool_len == 0 {
            da.generate(1).await?;

            let retried_mempool_len = observe_commit_reveal_mempool_len(da).await?;
            assert_atomic_commit_reveal_result(
                retried_mempool_len,
                "after retrying queued transactions on a new DA block",
            );
        }

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
