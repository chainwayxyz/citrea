use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use alloy_primitives::U64;
use anyhow::bail;
use async_trait::async_trait;
use bitcoin_da::rpc::DaRpcClient;
use citrea_e2e::config::SequencerConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::Config;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::{NodeT, Restart};
use citrea_e2e::Result;
use reth_primitives::BlockNumberOrTag;
use sov_ledger_rpc::LedgerRpcClient;

use super::get_citrea_path;
use crate::evm::make_test_client;

struct BasicSequencerTest;

#[async_trait]
impl TestCase for BasicSequencerTest {
    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let Some(sequencer) = &f.sequencer else {
            anyhow::bail!("Sequencer not running. Set TestCaseConfig with_sequencer to true")
        };

        let Some(da) = f.bitcoin_nodes.get(0) else {
            bail!("bitcoind not running. Test cannot run with bitcoind runnign as DA")
        };

        sequencer.client.send_publish_batch_request().await?;

        let head_batch0 = sequencer
            .client
            .http_client()
            .get_head_soft_confirmation()
            .await?
            .unwrap();
        assert_eq!(head_batch0.l2_height, 1);

        sequencer.client.send_publish_batch_request().await?;

        da.generate(1).await?;

        sequencer.client.wait_for_l2_block(1, None).await?;
        let head_batch1 = sequencer
            .client
            .http_client()
            .get_head_soft_confirmation()
            .await?
            .unwrap();
        assert_eq!(head_batch1.l2_height, 2);

        Ok(())
    }
}

#[tokio::test]
async fn basic_sequencer_test() -> Result<()> {
    TestCaseRunner::new(BasicSequencerTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// This test checks the sequencer behavior when missed DA blocks are detected.
/// 1. Run the sequencer.
/// 2. Create a L2 blocks on top of an L1.
/// 3. Shutdown sequencer
/// 4. Create a bunch of L1 blocks.
/// 5. Start the sequencer.
///
/// Each DA block should have a L2 block created for it.
struct SequencerMissedDaBlocksTest;

#[async_trait]
impl TestCase for SequencerMissedDaBlocksTest {
    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 1000,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_mut().unwrap();
        let da = f.bitcoin_nodes.get(0).unwrap();

        let initial_l1_height = da.get_finalized_height().await?;

        // Create initial DA blocks
        da.generate(3).await?;

        sequencer.client.send_publish_batch_request().await?;

        sequencer.wait_until_stopped().await?;

        // Create 10 more DA blocks while the sequencer is down
        da.generate(10).await?;

        // Restart the sequencer
        sequencer.start(None).await?;

        for _ in 0..10 {
            sequencer.client.send_publish_batch_request().await?;
        }

        let head_soft_confirmation_height = sequencer
            .client
            .ledger_get_head_soft_confirmation_height()
            .await?;

        let mut last_used_l1_height = initial_l1_height;

        // check that the sequencer has at least one block for each DA block
        // starting from DA #3 all the way up to DA #13 without no gaps
        // the first soft confirmation should be on DA #3
        // the last soft confirmation should be on DA #13
        for i in 1..=head_soft_confirmation_height {
            let soft_confirmation = sequencer
                .client
                .http_client()
                .get_soft_confirmation_by_number(U64::from(i))
                .await?
                .unwrap();

            if i == 1 {
                assert_eq!(soft_confirmation.da_slot_height, last_used_l1_height);
            } else {
                assert!(
                    soft_confirmation.da_slot_height == last_used_l1_height
                        || soft_confirmation.da_slot_height == last_used_l1_height + 1,
                );
            }

            last_used_l1_height = soft_confirmation.da_slot_height;
        }

        let finalized_height = da.get_finalized_height().await?;
        assert_eq!(last_used_l1_height, finalized_height);

        Ok(())
    }
}

#[tokio::test]
async fn test_sequencer_missed_da_blocks() -> Result<()> {
    TestCaseRunner::new(SequencerMissedDaBlocksTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct DaThrottleTest;

#[async_trait]
impl TestCase for DaThrottleTest {
    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");

        let seq_config = sequencer.config();
        let seq_test_client = make_test_client(SocketAddr::new(
            seq_config.rpc_bind_host().parse()?,
            seq_config.rpc_bind_port(),
        ))
        .await?;

        let base_l1_fee_rate = 2_500_000_000f64;

        // Get initial usage stats
        let initial_usage = sequencer.client.http_client().da_usage_window().await?;
        assert_eq!(initial_usage.total_bytes, 0);
        assert_eq!(initial_usage.usage_ratio, 0.0);

        sequencer.client.send_publish_batch_request().await?;
        sequencer.wait_for_l2_height(1, None).await?;

        let seq_block = seq_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
            .await;

        let l1_fee_rate = seq_block.other.get("l1FeeRate").unwrap().as_f64().unwrap();
        assert_eq!(l1_fee_rate, base_l1_fee_rate);

        // Generate seqcommitments to increase DA usage
        for _ in 0..sequencer.min_soft_confirmations_per_commitment() - 1 {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for tx to hit mempool and check DA usage increased
        da.wait_mempool_len(2, None).await?;
        let da_usage = sequencer.client.http_client().da_usage_window().await?;
        assert!(da_usage.total_bytes > 0);
        assert!(da_usage.usage_ratio > 0.0);

        // Generate more seqcoms to exceed threshold
        let n_txs = 3;
        for _ in 0..n_txs {
            for _ in 0..sequencer.min_soft_confirmations_per_commitment() {
                sequencer.client.send_publish_batch_request().await?;
            }
        }
        da.wait_mempool_len(2 + 2 * n_txs, None).await?;

        // Check that usage is above threshold and multiplier > 1
        let usage_after_seqcom = sequencer.client.http_client().da_usage_window().await?;
        assert!(usage_after_seqcom.total_bytes > da_usage.total_bytes);
        assert!(usage_after_seqcom.usage_ratio > da_usage.usage_ratio);
        assert!(usage_after_seqcom.fee_multiplier > Some(1.0));

        sequencer.client.send_publish_batch_request().await?;

        let seq_block = seq_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
            .await;
        let throttled_l1_fee_rate = seq_block.other.get("l1FeeRate").unwrap().as_f64().unwrap();
        assert_eq!(
            throttled_l1_fee_rate,
            (base_l1_fee_rate * usage_after_seqcom.fee_multiplier.unwrap()).floor()
        );

        // Check that usage window is correclty resetted on interval
        let interval = seq_config
            .rollup_config()
            .da
            .monitoring
            .as_ref()
            .unwrap()
            .window_duration_secs;
        let next_reset = interval
            - (SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - da_usage.start_time);

        // Sleep until next_reset + a 1s buffer
        tokio::time::sleep(Duration::from_secs(next_reset + 1)).await;
        let resetted_usage = sequencer.client.http_client().da_usage_window().await?;
        assert_eq!(resetted_usage.total_bytes, 0);
        assert_eq!(resetted_usage.usage_ratio, 0.0);
        assert_eq!(resetted_usage.fee_multiplier, Some(1.0));
        assert_eq!(resetted_usage.start_time, da_usage.start_time + interval);

        sequencer.client.send_publish_batch_request().await?;

        let seq_block = seq_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
            .await;
        let l1_fee_rate = seq_block.other.get("l1FeeRate").unwrap().as_f64().unwrap();
        assert_eq!(l1_fee_rate, base_l1_fee_rate);
        Ok(())
    }
}

#[tokio::test]
async fn test_da_throttle() -> Result<()> {
    TestCaseRunner::new(DaThrottleTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
