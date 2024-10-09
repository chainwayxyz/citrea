use async_trait::async_trait;
use bitcoin_da::service::{get_relevant_blobs_from_txs};
use bitcoincore_rpc::RpcApi;
use borsh::BorshDeserialize;
use citrea_e2e::bitcoin::BitcoinNode;
use citrea_e2e::config::{
    BatchProverConfig, LightClientProverConfig, SequencerConfig, TestCaseConfig,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::sequencer::Sequencer;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_primitives::REVEAL_BATCH_PROOF_PREFIX;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_rollup_interface::da::{BlobReaderTrait, DaData};

struct LightClientProvingTest;

#[async_trait]
impl TestCase for LightClientProvingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            ..Default::default()
        }
    }
    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 5,
            da_update_interval_ms: 500,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            enable_recovery: false,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            ..Default::default()
        }
    }

    // TODO: write something meaningful
    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let initial_height = f.initial_da_height;
        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        // publish min_soft_confirmations_per_commitment confirmations
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
            .await?;

        Ok(())
    }
}

impl LightClientProvingTest {
    async fn check_sequencer_commitment(
        &self,
        sequencer: &Sequencer,
        da: &BitcoinNode,
        start_l2_block: u64,
        end_l2_block: u64,
    ) -> Result<()> {
        let finalized_height = da.get_finalized_height().await?;

        // Extract and verify the commitment from the block
        let hash = da.get_block_hash(finalized_height).await?;
        let block = da.get_block(&hash).await?;

        let mut blobs = get_relevant_blobs_from_txs(block.txdata, REVEAL_BATCH_PROOF_PREFIX);

        assert_eq!(blobs.len(), 1);

        let mut blob = blobs.pop().unwrap();

        let data = BlobReaderTrait::full_data(&mut blob);

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
                    .ledger_get_soft_confirmation_by_number(i)
                    .await?
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
async fn test_light_client_proving() -> Result<()> {
    TestCaseRunner::new(LightClientProvingTest).run().await
}
