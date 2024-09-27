use anyhow::bail;
use async_trait::async_trait;
use bitcoin_da::spec::BitcoinSpec;
use bitcoincore_rpc::RpcApi;
use citrea_sequencer::SequencerConfig;

use crate::bitcoin_e2e::framework::TestFramework;
use crate::bitcoin_e2e::node::{L2Node, Restart};
use crate::bitcoin_e2e::test_case::{TestCase, TestCaseRunner};
use crate::bitcoin_e2e::Result;

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

        let seq_height0 = sequencer.client.eth_block_number().await;
        assert_eq!(seq_height0, 0);

        sequencer.client.send_publish_batch_request().await;
        da.generate(1, None).await?;

        sequencer.wait_for_l2_height(1, None).await;
        let seq_height1 = sequencer.client.eth_block_number().await;
        assert_eq!(seq_height1, 1);

        Ok(())
    }
}

#[tokio::test]
async fn basic_sequencer_test() -> Result<()> {
    TestCaseRunner::new(BasicSequencerTest).run().await
}

/// This test checks the sequencer behavior when missed DA blocks are detected.
/// 1. Run the sequencer.
/// 2. Create a L2 blocks on top of an L1.
/// 3. Shutdown sequencer
/// 4. Create a bunch of L1 blocks.
/// 5. Start the sequencer.
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
        println!("initial_l1_height : {:?}", initial_l1_height);
        println!(
            "da.get_block_count().await? : {:?}",
            da.get_block_count().await?
        );

        // Create initial DA blocks
        da.generate(3, None).await?;

        sequencer.client.send_publish_batch_request().await;

        sequencer.wait_until_stopped().await?;

        // Create 10 more DA blocks while the sequencer is down
        da.generate(10, None).await?;

        // Restart the sequencer
        sequencer.start(None).await?;

        for _ in 0..3 {
            sequencer.client.send_publish_batch_request().await;
        }

        let head_soft_confirmation_height = sequencer
            .client
            .ledger_get_head_soft_confirmation_height()
            .await
            .unwrap()
            .unwrap();

        let mut last_used_l1_height = initial_l1_height;

        // check that the sequencer has at least one block for each DA block
        // starting from DA #3 all the way up to DA #13 without no gaps
        // the first soft confirmation should be on DA #3
        // the last soft confirmation should be on DA #13
        for i in 1..=head_soft_confirmation_height {
            let soft_confirmation = sequencer
                .client
                .ledger_get_soft_confirmation_by_number::<BitcoinSpec>(i)
                .await
                .unwrap();

            println!("i {i}, soft_confirmation : {:?}", soft_confirmation);
            if i == 1 {
                assert_eq!(soft_confirmation.da_slot_height, last_used_l1_height);
            } else {
                assert!(
                    soft_confirmation.da_slot_height == last_used_l1_height
                        || soft_confirmation.da_slot_height == last_used_l1_height + 1,
                );
            }

            last_used_l1_height = soft_confirmation.da_slot_height;
            println!("i {i}, last_used_l1_height : {:?}", last_used_l1_height);
        }

        let finalized_height = da.get_finalized_height().await?;
        println!("finalized_height at end : {:?}", finalized_height);
        println!(
            "da.get_block_count().await? at end: {:?}",
            da.get_block_count().await?
        );
        assert_eq!(last_used_l1_height, finalized_height);

        Ok(())
    }
}

#[tokio::test]
async fn test_sequencer_missed_da_blocks() -> Result<()> {
    TestCaseRunner::new(SequencerMissedDaBlocksTest).run().await
}
