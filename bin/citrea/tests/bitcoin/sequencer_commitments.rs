use std::time::{Duration, Instant};

use alloy_primitives::{U32, U64};
use anyhow::bail;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoincore_rpc::RpcApi;
use borsh::BorshDeserialize;
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_e2e::bitcoin::{BitcoinNode, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::config::{SequencerConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::{FullNode, NodeKind, Sequencer};
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use citrea_primitives::REVEAL_TX_PREFIX;
use citrea_sequencer::SequencerRpcClient;
use reth_tasks::TaskManager;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::da::{BlobReaderTrait, DaTxRequest, DataOnDa, SequencerCommitment};
use sov_rollup_interface::rpc::SequencerCommitmentResponse;
use tokio::time::sleep;

use super::get_citrea_path;
use crate::bitcoin::get_relevant_seqcoms_from_txs;
use crate::bitcoin::utils::spawn_bitcoin_da_with_wallet;

pub async fn wait_for_sequencer_commitments(
    full_node: &FullNode,
    height: u64,
    timeout: Option<Duration>,
) -> Result<Vec<SequencerCommitmentResponse>> {
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(120));

    loop {
        if start.elapsed() >= timeout {
            bail!("FullNode failed to get sequencer commitments within the specified timeout");
        }

        match full_node
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(U64::from(height))
            .await
        {
            Ok(Some(commitments)) => return Ok(commitments),
            Ok(None) => sleep(Duration::from_millis(500)).await,
            Err(e) => bail!("Error fetching sequencer commitments: {}", e),
        }
    }
}

struct LedgerGetCommitmentsProverTest;

#[async_trait]
impl TestCase for LedgerGetCommitmentsProverTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig::default()
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let prover = f.batch_prover.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        // Include commitment in block and finalize it
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        // wait here until we see from prover's rpc that it finished proving
        prover.wait_for_l1_height(finalized_height, None).await?;

        let commitment_indices = prover
            .client
            .http_client()
            .get_commitment_indices_by_l1(finalized_height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitment_indices.len(), 1);

        let commitment = prover
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(commitment_indices[0]))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            commitment.l2_end_block_number.to::<u64>(),
            max_l2_blocks_per_commitment
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_ledger_get_commitments_on_slot_prover() -> Result<()> {
    TestCaseRunner::new(LedgerGetCommitmentsProverTest)
        .set_citrea_path(get_citrea_path())
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

    fn scan_l1_start_height() -> Option<u64> {
        Some(146)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let full_node = f.full_node.as_ref().unwrap();
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // disable this since it's the only difference from other tests??
        // da.generate(1).await?;

        // sequencer.client.send_publish_batch_request().await?;

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        // Generate enough block to finalize
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        full_node
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;

        let finalized_height = da.get_finalized_height(None).await?;

        let commitments = wait_for_sequencer_commitments(full_node, finalized_height, None).await?;

        assert_eq!(commitments.len(), 1);

        assert_eq!(
            commitments[0].l2_end_block_number.to::<u64>(),
            max_l2_blocks_per_commitment
        );

        let hash = da.get_block_hash(finalized_height).await?;

        let commitments_node = full_node
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_hash(hash.as_raw_hash().to_byte_array().into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments_node, commitments);
        Ok(())
    }
}

#[tokio::test]
async fn test_ledger_get_commitments_on_slot_full_node() -> Result<()> {
    TestCaseRunner::new(LedgerGetCommitmentsTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct SequencerSendCommitmentsToDaTest;

#[async_trait]
impl TestCase for SequencerSendCommitmentsToDaTest {
    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: DEFAULT_FINALITY_DEPTH * 2,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        // publish max_l2_blocks_per_commitment - 1 confirmations, no commitments should be sent
        for _ in 0..max_l2_blocks_per_commitment - 1 {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment - 1, None)
            .await?;

        // Publish one more L2 block and send commitment
        sequencer.client.send_publish_batch_request().await?;

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        // Include commitment in block and finalize it
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        tokio::time::sleep(Duration::from_millis(1)).await;

        let start_l2_block = 1;
        let end_l2_block = sequencer.client.ledger_get_head_l2_block_height().await?;

        self.check_sequencer_commitment(sequencer, da, start_l2_block, end_l2_block)
            .await?;

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;
        // Include commitment in block and finalize it
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let start_l2_block = end_l2_block + 1;
        let end_l2_block = end_l2_block + max_l2_blocks_per_commitment;

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
        let finalized_height = da.get_finalized_height(None).await?;

        // Extract and verify the commitment from the block
        let hash = da.get_block_hash(finalized_height).await?;
        let block = da.get_block(&hash).await?;

        let mut blobs = get_relevant_seqcoms_from_txs(block.txdata, REVEAL_TX_PREFIX);

        assert_eq!(blobs.len(), 1);

        let blob = blobs.pop().unwrap();

        let data = blob.full_data();

        let commitment = DataOnDa::try_from_slice(data).unwrap();

        let DataOnDa::SequencerCommitment(commitment) = commitment else {
            panic!("Expected SequencerCommitment, got {:?}", commitment);
        };

        let mut l2_blocks = Vec::new();

        for i in start_l2_block..=end_l2_block {
            l2_blocks.push(
                sequencer
                    .client
                    .http_client()
                    .get_l2_block_by_number(U64::from(i))
                    .await?
                    .unwrap(),
            );
        }

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(
            l2_blocks
                .iter()
                .map(|x| x.header.hash)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        assert_eq!(commitment.l2_end_block_number, end_l2_block);
        assert_eq!(commitment.merkle_root, merkle_tree.root().unwrap());
        Ok(())
    }
}

#[tokio::test]
async fn test_sequencer_sends_commitments_to_da_layer() -> Result<()> {
    TestCaseRunner::new(SequencerSendCommitmentsToDaTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

// Test commitment service fetching commitments from DA layer and storing them if their index is higher than the last stored one
struct SequencerCommitmentsFromDaTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for SequencerCommitmentsFromDaTest {
    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_mut().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");

        let da_service = spawn_bitcoin_da_with_wallet(
            &self.task_manager.executor(),
            &da.config,
            NodeKind::Sequencer.to_string(),
        )
        .await;

        // publish blocks, no commitments should be sent
        sequencer.client.http_client().halt_commitments().await?;
        for _ in 0..40 {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer.wait_for_l2_height(40, None).await?;
        sequencer.wait_until_stopped().await?;

        // Send commitment with index 1 to DA
        let commitment = SequencerCommitment {
            merkle_root: [1; 32],
            l2_end_block_number: 15,
            index: 1,
        };
        da_service
            .send_transaction_with_fee_rate(DaTxRequest::SequencerCommitment(commitment), 1)
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Send commitment with index 2 to DA, but don't mine it yet
        let commitment = SequencerCommitment {
            merkle_root: [2; 32],
            l2_end_block_number: 25,
            index: 2,
        };
        da_service
            .send_transaction_with_fee_rate(DaTxRequest::SequencerCommitment(commitment), 1)
            .await
            .unwrap();
        // Restart sequencer, it should fetch commitment with index 1 and 2
        sequencer.restart(None, None).await?;
        // Sequencer should submit the next commitment with index 3
        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        // Check if sequencer fetched commitment 1
        let comm_1 = sequencer
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(1))
            .await?
            .unwrap();
        assert_eq!(comm_1.index, U32::from(1));
        assert_eq!(comm_1.l2_end_block_number, U64::from(15));
        assert_eq!(comm_1.merkle_root, [1; 32]);

        // Check if sequencer fetched commitment 2
        let comm_2 = sequencer
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(2))
            .await?
            .unwrap();
        assert_eq!(comm_2.index, U32::from(2));
        assert_eq!(comm_2.l2_end_block_number, U64::from(25));
        assert_eq!(comm_2.merkle_root, [2; 32]);

        // Check if sequencer submitted commitment 3 for blocks 26-35
        let comm_3 = sequencer
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(3))
            .await?
            .unwrap();
        assert_eq!(comm_3.index, U32::from(3));
        assert_eq!(comm_3.l2_end_block_number, U64::from(35));

        // Calculate root
        let mut l2_blocks = Vec::new();
        for i in 26..=35 {
            l2_blocks.push(
                sequencer
                    .client
                    .http_client()
                    .get_l2_block_by_number(U64::from(i))
                    .await?
                    .unwrap(),
            );
        }
        let merkle_tree = MerkleTree::<Sha256>::from_leaves(
            l2_blocks
                .iter()
                .map(|x| x.header.hash)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        // Compare merkle roots
        assert_eq!(comm_3.merkle_root, merkle_tree.root().unwrap());
        Ok(())
    }
}

#[tokio::test]
async fn test_sequencer_commitments_from_da_layer() -> Result<()> {
    TestCaseRunner::new(SequencerCommitmentsFromDaTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}
