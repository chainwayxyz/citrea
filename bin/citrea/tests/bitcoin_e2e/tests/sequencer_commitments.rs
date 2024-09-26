use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin_da::service::FINALITY_DEPTH;
use bitcoin_da::spec::BitcoinSpec;
use bitcoincore_rpc::RpcApi;
use borsh::BorshDeserialize;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::DaData;

use crate::bitcoin_e2e::bitcoin::BitcoinNode;
use crate::bitcoin_e2e::config::{SequencerConfig, TestCaseConfig};
use crate::bitcoin_e2e::framework::TestFramework;
use crate::bitcoin_e2e::node::L2Node;
use crate::bitcoin_e2e::sequencer::Sequencer;
use crate::bitcoin_e2e::test_case::{TestCase, TestCaseRunner};
use crate::bitcoin_e2e::Result;

struct LedgerGetCommitmentsProverTest;

#[async_trait]
impl TestCase for LedgerGetCommitmentsProverTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_prover: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig::default()
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let prover = f.prover.as_ref().unwrap();

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await;
        }
        sequencer
            .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
            .await;

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(1, None).await?;

        // Include commitment in block and finalize it
        da.generate(FINALITY_DEPTH, None).await?;

        let finalized_height = da.get_finalized_height().await?;

        // wait here until we see from prover's rpc that it finished proving
        prover.wait_for_l1_height(finalized_height, None).await?;

        let commitments = prover
            .client
            .ledger_get_sequencer_commitments_on_slot_by_number(finalized_height)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(commitments.len(), 1);

        assert_eq!(commitments[0].l2_start_block_number, 1);
        assert_eq!(commitments[0].l2_end_block_number, 4);

        assert_eq!(commitments[0].found_in_l1, finalized_height);

        let hash = da.get_block_hash(finalized_height).await?;

        let commitments_hash = prover
            .client
            .ledger_get_sequencer_commitments_on_slot_by_hash(hash.as_raw_hash().to_byte_array())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments_hash, commitments);
        Ok(())
    }
}

#[tokio::test]
async fn test_ledger_get_commitments_on_slot_prover() -> Result<()> {
    TestCaseRunner::new(LedgerGetCommitmentsProverTest)
        .run()
        .await
}

struct LedgerGetCommitmentsTest;

#[async_trait]
impl TestCase for LedgerGetCommitmentsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig::default()
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let full_node = f.full_node.as_ref().unwrap();
        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await;
        }

        // disable this since it's the only difference from other tests??
        // da.generate(1, None).await?;

        // sequencer.client.send_publish_batch_request().await;

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(1, None).await?;

        // Generate enough block to finalize
        da.generate(FINALITY_DEPTH, None).await?;

        full_node
            .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
            .await;

        let finalized_height = da.get_finalized_height().await?;

        let commitments = full_node
            .wait_for_sequencer_commitments(finalized_height, None)
            .await?;

        assert_eq!(commitments.len(), 1);

        assert_eq!(commitments[0].l2_start_block_number, 1);
        assert_eq!(commitments[0].l2_end_block_number, 4);

        assert_eq!(commitments[0].found_in_l1, finalized_height);

        let hash = da.get_block_hash(finalized_height).await?;

        let commitments_node = full_node
            .client
            .ledger_get_sequencer_commitments_on_slot_by_hash(hash.as_raw_hash().to_byte_array())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments_node, commitments);
        Ok(())
    }
}

#[tokio::test]
async fn test_ledger_get_commitments_on_slot_full_node() -> Result<()> {
    TestCaseRunner::new(LedgerGetCommitmentsTest).run().await
}

struct SequencerSendCommitmentsToDaTest;

#[async_trait]
impl TestCase for SequencerSendCommitmentsToDaTest {
    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 12,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");

        let initial_height = f.initial_da_height;
        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        // publish min_soft_confirmations_per_commitment - 1 confirmations, no commitments should be sent
        for _ in 0..min_soft_confirmations_per_commitment - 1 {
            sequencer.client.send_publish_batch_request().await;
        }
        sequencer
            .wait_for_l2_height(min_soft_confirmations_per_commitment - 1, None)
            .await;

        da.generate(FINALITY_DEPTH, None).await?;
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

        let finalized_height = da.get_finalized_height().await?;

        for height in initial_height..finalized_height {
            let mut blobs = da.get_relevant_blobs_from_block(height).await?;

            for mut blob in blobs.drain(0..) {
                let data = blob.full_data();

                assert_eq!(data, &[] as &[u8]);
            }
        }

        // Publish one more L2 block and send commitment
        sequencer.client.send_publish_batch_request().await;

        sequencer
            .wait_for_l2_height(
                min_soft_confirmations_per_commitment + FINALITY_DEPTH - 1,
                None,
            )
            .await;

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(1, None).await?;

        // Include commitment in block and finalize it
        da.generate(FINALITY_DEPTH, None).await?;
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

        let start_l2_block = 1;
        let end_l2_block = 19;

        self.check_sequencer_commitment(sequencer, da, start_l2_block, end_l2_block)
            .await?;

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await;
        }
        sequencer
            .wait_for_l2_height(
                end_l2_block + min_soft_confirmations_per_commitment + FINALITY_DEPTH - 2,
                None,
            )
            .await;

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(1, None).await?;
        // Include commitment in block and finalize it
        da.generate(FINALITY_DEPTH, None).await?;

        let start_l2_block = end_l2_block + 1;
        let end_l2_block = end_l2_block + 12;

        self.check_sequencer_commitment(sequencer, da, start_l2_block, end_l2_block)
            .await?;

        Ok(())
    }
}

impl SequencerSendCommitmentsToDaTest {
    async fn check_sequencer_commitment(
        &self,
        sequencer: &Sequencer,
        da: &BitcoinNode,
        start_l2_block: u64,
        end_l2_block: u64,
    ) -> Result<()> {
        let finalized_height = da.get_finalized_height().await?;

        // Extract and verify the commitment from the block
        let mut blobs = da.get_relevant_blobs_from_block(finalized_height).await?;

        assert_eq!(blobs.len(), 1);

        let mut blob = blobs.pop().unwrap();

        let data = blob.full_data();

        let commitment = DaData::try_from_slice(data).unwrap();

        matches!(commitment, DaData::SequencerCommitment(_));

        let DaData::SequencerCommitment(commitment) = commitment else {
            panic!("Expected SequencerCommitment, got {:?}", commitment);
        };

        let mut soft_confirmations = Vec::new();

        for i in start_l2_block..=end_l2_block {
            soft_confirmations.push(
                sequencer
                    .client
                    .ledger_get_soft_confirmation_by_number::<BitcoinSpec>(i)
                    .await
                    .unwrap(),
            );
        }

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(
            soft_confirmations
                .iter()
                .map(|x| x.hash)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        assert_eq!(commitment.l2_start_block_number, start_l2_block);
        assert_eq!(commitment.l2_end_block_number, end_l2_block);
        assert_eq!(commitment.merkle_root, merkle_tree.root().unwrap());
        Ok(())
    }
}

#[tokio::test]
async fn test_sequencer_sends_commitments_to_da_layer() -> Result<()> {
    TestCaseRunner::new(SequencerSendCommitmentsToDaTest)
        .run()
        .await
}
