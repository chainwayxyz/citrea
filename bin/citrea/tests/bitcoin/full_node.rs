use std::time::Duration;

use alloy_primitives::{U32, U64};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use bitcoin_da::helpers::parsers::{parse_relevant_transaction, ParsedTransaction};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{
    BatchProverConfig, BitcoinConfig, LightClientProverConfig, SequencerConfig, TestCaseConfig,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use citrea_fullnode::rpc::FullNodeRpcClient;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use reth_tasks::TaskManager;
use risc0_zkvm::{FakeReceipt, InnerReceipt, MaybePruned, ReceiptClaim};
use sov_db::schema::types::L2HeightAndIndex;
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::BatchProofCircuitOutputV3;
use sov_rollup_interface::da::{DaTxRequest, SequencerCommitment};
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::zk::batch_proof::output::{BatchProofCircuitOutput, CumulativeStateDiff};
use tokio::time::sleep;

use super::light_client_test::{create_random_state_diff, TEN_MINS};
use super::{get_citrea_cli_path, get_citrea_path};
use crate::bitcoin::utils::{
    spawn_bitcoin_da_service, wait_for_prover_job, wait_for_prover_job_count, wait_for_zkproofs,
    DaServiceKeyKind,
};

fn calculate_merkle_root(blocks: &[Option<L2BlockResponse>]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = blocks
        .iter()
        .flatten()
        .map(|block| block.header.hash)
        .collect();

    let tree = rs_merkle::MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&leaves);
    tree.root().unwrap()
}

struct PreStateRootMismatchTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for PreStateRootMismatchTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_light_client_prover: true,
            with_sequencer: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-persistmempool=0", "-walletbroadcast=0"],
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(175)
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            initial_da_height: 175,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let task_executor = self.task_manager.executor();

        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let prover_da_service = spawn_bitcoin_da_service(
            task_executor.clone(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment1_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(commitment1_l1_height, None)
            .await?;
        let commitment_response = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(1))
            .await?
            .unwrap();

        let commitment1 = SequencerCommitment {
            merkle_root: commitment_response.merkle_root,
            index: commitment_response.index.to::<u32>(),
            l2_end_block_number: commitment_response.l2_end_block_number.to::<u64>(),
        };

        light_client_prover
            .wait_for_l1_height(commitment1_l1_height, None)
            .await?;

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        let l1_hash = da.get_block_hash(commitment1_l1_height).await?;

        let genesis_state_root = full_node
            .client
            .http_client()
            .get_l2_genesis_state_root()
            .await?
            .unwrap()
            .0;

        // First proof
        let proof = create_serialized_fake_receipt_batch_proof_with_state_roots(
            genesis_state_root.try_into().unwrap(),
            max_l2_blocks_per_commitment,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![commitment1.clone()],
            vec![commitment_response.merkle_root],
            None,
        );

        // Send the first proof
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(proof), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof1_l1_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(proof1_l1_height, None).await?;

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment2_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(commitment2_l1_height, None)
            .await?;

        let commitment_response2 = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(2))
            .await?
            .unwrap();

        let commitment2 = SequencerCommitment {
            merkle_root: commitment_response2.merkle_root,
            index: commitment_response2.index.to::<u32>(),
            l2_end_block_number: commitment_response2.l2_end_block_number.to::<u64>(),
        };

        light_client_prover
            .wait_for_l1_height(commitment2_l1_height, None)
            .await?;

        // Get batch proof method IDs and L1 hash
        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        let l1_hash = da.get_block_hash(commitment2_l1_height).await?;

        let commitment_2_state_root = sequencer
            .client
            .http_client()
            .get_l2_block_by_number(U64::from(commitment2.l2_end_block_number))
            .await?
            .unwrap()
            .header
            .state_root;

        // Invalid proof with invalid starting state root
        let invalid_proof = create_serialized_fake_receipt_batch_proof_with_state_roots(
            [1; 32], // Invalid state root
            max_l2_blocks_per_commitment * 2,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![commitment2.clone()],
            vec![commitment_2_state_root],
            Some(commitment1.serialize_and_calculate_sha_256()),
        );

        // Send the invalid proof
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(invalid_proof), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let invalid_proof_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(invalid_proof_l1_height, None)
            .await?;

        // Assert that proof wasn't accepted and is correctly discarded due to pre state root mismatch
        let proofs = full_node
            .client
            .http_client()
            .get_verified_batch_proofs_by_slot_height(U64::from(invalid_proof_l1_height))
            .await?;
        assert!(proofs.is_none());

        // Generate 1 blocks and assert that L1 sync is not halted and full node continues syncing
        da.generate(1).await?;
        full_node
            .wait_for_l1_height(invalid_proof_l1_height + 1, None)
            .await?;
        let final_scanned_l1_height = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await?;
        assert_eq!(
            final_scanned_l1_height.to::<u64>(),
            invalid_proof_l1_height + 1,
        );

        // Verify the first proof is still the only valid one
        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();

        assert_eq!(proven_height.height, max_l2_blocks_per_commitment);
        assert_eq!(proven_height.commitment_index, 1);

        Ok(())
    }
}

#[tokio::test]
async fn test_pre_state_root_mismatch() -> Result<()> {
    TestCaseRunner::new(PreStateRootMismatchTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct SequencerCommitmentHashMismatchTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for SequencerCommitmentHashMismatchTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_light_client_prover: true, // Used for getting batch_proof_method_ids
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-persistmempool=0", "-walletbroadcast=0"],
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            initial_da_height: 171,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let task_executor = self.task_manager.executor();

        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let prover_da_service = spawn_bitcoin_da_service(
            task_executor.clone(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;
        let sequencer_da_service = spawn_bitcoin_da_service(
            task_executor,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;

        da.restart(None, None).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 0);

        let range1 = sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), U64::from(max_l2_blocks_per_commitment))
            .await?;
        let correct_merkle_root = calculate_merkle_root(&range1);

        let correct_commitment = SequencerCommitment {
            merkle_root: correct_merkle_root,
            l2_end_block_number: max_l2_blocks_per_commitment,
            index: 1,
        };

        let wrong_merkle_root = [1; 32];
        let wrong_commitment = SequencerCommitment {
            merkle_root: wrong_merkle_root,
            l2_end_block_number: max_l2_blocks_per_commitment,
            index: 1,
        };

        // Send the `correct_commitment` so it's stored and will trigger the pre-hash mismatch against `wrong_commitment`
        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(correct_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;

        // Wait for full node to process the commitment
        full_node
            .wait_for_l1_height(commitment_l1_height, None)
            .await?;
        light_client_prover
            .wait_for_l1_height(commitment_l1_height, None)
            .await
            .unwrap();

        // Verify the correct commitment is stored and has the expected merkle_root
        let stored_commitment = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(1))
            .await?
            .unwrap();
        assert_eq!(stored_commitment.merkle_root, correct_merkle_root);

        let finalized_height = da.get_finalized_height(None).await?;
        let l1_hash = da.get_block_hash(finalized_height).await?;

        let genesis_state_root = full_node
            .client
            .http_client()
            .get_l2_genesis_state_root()
            .await?
            .unwrap()
            .0;
        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        let wrong_commitment_state_root = sequencer
            .client
            .http_client()
            .get_l2_block_by_number(U64::from(wrong_commitment.l2_end_block_number))
            .await?
            .unwrap()
            .header
            .state_root;

        // Create a fake proof against the wrong commitment
        let fake_proof = create_serialized_fake_receipt_batch_proof_with_state_roots(
            genesis_state_root.try_into().unwrap(),
            max_l2_blocks_per_commitment,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![wrong_commitment.clone()],
            vec![wrong_commitment_state_root],
            None,
        );
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(fake_proof), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        // Assert that proof wasn't accepted and is correctly discarded due to hash mismatch
        let proofs = full_node
            .client
            .http_client()
            .get_verified_batch_proofs_by_slot_height(U64::from(proof_l1_height))
            .await?;
        assert!(proofs.is_none());

        // Generate 1 blocks and assert that L1 sync is not halted and full node continues syncing
        da.generate(1).await?;
        full_node
            .wait_for_l1_height(proof_l1_height + 1, None)
            .await?;
        let final_scanned_l1_height = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await?;
        assert_eq!(final_scanned_l1_height.to::<u64>(), proof_l1_height + 1,);

        Ok(())
    }
}

#[tokio::test]
async fn test_sequencer_commitment_hash_mismatch() -> Result<()> {
    TestCaseRunner::new(SequencerCommitmentHashMismatchTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct PendingCommitmentHaltingErrorTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for PendingCommitmentHaltingErrorTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-persistmempool=0", "-walletbroadcast=0"],
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let task_executor = self.task_manager.executor();

        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_mut().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            task_executor,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        // This should cause a halting error as merkle root doesn't match the expected root from known L2 blocks
        // Send it first then generate block so that it's pending then causes a mismatch
        let wrong_merkle_root_commitment = SequencerCommitment {
            merkle_root: [0xAA; 32], // Wrong merkle root
            l2_end_block_number: max_l2_blocks_per_commitment,
            index: 1,
        };

        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(wrong_merkle_root_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(l1_height, None).await?;

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for l2 blocks and make sure the node is halted
        full_node
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;
        // Generate a block and make sure fullnode doesn't process it
        da.generate(1).await?;

        // Sleep to trigger L1 block processing
        sleep(Duration::from_secs(1)).await;

        // Check that the full node has stopped processing L1 blocks due to halting error
        let last_scanned_l1_height = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await?;

        // The full node should be halted at commitment height + 1
        // It is processed and kept as pending at commitment height.
        // Next block triggers the HaltingError
        assert_eq!(last_scanned_l1_height.to::<u64>(), l1_height);

        // Verify that no commitment were processed
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?;
        assert!(committed_height.is_none());

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Assert that full node can still process L2 blocks
        full_node
            .wait_for_l2_height(max_l2_blocks_per_commitment * 2, None)
            .await?;

        // Generate 5 blocks and assert that L1 sync is halted
        da.generate(5).await?;
        let final_scanned_l1_height = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await?;
        assert_eq!(
            final_scanned_l1_height.to::<u64>(),
            last_scanned_l1_height.to::<u64>(),
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_halting_pending_commitment_merkle_root_mismatch() -> Result<()> {
    TestCaseRunner::new(PendingCommitmentHaltingErrorTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct FullNodeRestartTest;

#[async_trait]
impl TestCase for FullNodeRestartTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_mut().unwrap();

        let genesis_state_root = full_node
            .client
            .http_client()
            .get_l2_genesis_state_root()
            .await?
            .unwrap();

        full_node.restart(None, None).await?;

        let genesis_state_root_after = full_node
            .client
            .http_client()
            .get_l2_genesis_state_root()
            .await?
            .unwrap();

        // Verify genesis is not reprocessed
        assert_eq!(genesis_state_root.0, genesis_state_root_after.0);

        sequencer.client.send_publish_batch_request().await?;
        full_node.wait_for_l2_height(1, None).await?;

        let state_root_before = full_node
            .client
            .http_client()
            .get_head_l2_block()
            .await?
            .unwrap()
            .header
            .state_root;

        full_node.restart(None, None).await?;

        let state_root_after = full_node
            .client
            .http_client()
            .get_head_l2_block()
            .await?
            .unwrap()
            .header
            .state_root;

        // Verify state root persists across restarts
        assert_eq!(state_root_before, state_root_after);

        Ok(())
    }
}

#[tokio::test]
async fn test_full_node_restart() -> Result<()> {
    TestCaseRunner::new(FullNodeRestartTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct L2StatusTest;

#[async_trait]
impl TestCase for L2StatusTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_full_node: true,
            with_citrea_cli: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let citrea_cli = f.citrea_cli.as_ref().unwrap();
        let full_node_http_client = full_node.client.http_client().clone();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let initial_committed_height = full_node_http_client.get_last_committed_l2_height().await?;
        assert_eq!(initial_committed_height, None);

        let initial_proven_height = full_node_http_client.get_last_proven_l2_height().await?;
        assert_eq!(initial_proven_height, None);

        let initial_heights_by_l1 = full_node_http_client
            .get_l2_status_heights_by_l1_height(0)
            .await?;
        assert_eq!(initial_heights_by_l1.committed.height, 0);
        assert_eq!(initial_heights_by_l1.proven.height, 0);

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(commitment_l1_height, None)
            .await?;

        let committed_height = full_node_http_client
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        assert_eq!(committed_height.height, max_l2_blocks_per_commitment);
        assert_eq!(committed_height.commitment_index, 1);

        let proven_height = full_node_http_client.get_last_proven_l2_height().await?;

        assert!(proven_height.is_none());

        let status_at_commitment_l1_height = full_node_http_client
            .get_l2_status_heights_by_l1_height(commitment_l1_height)
            .await?;
        assert_eq!(
            status_at_commitment_l1_height.committed.height,
            max_l2_blocks_per_commitment
        );
        assert_eq!(status_at_commitment_l1_height.proven.height, 0);

        batch_prover
            .wait_for_l1_height(commitment_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(batch_proof_l1_height, None)
            .await?;

        // Check that the proof was properly stored
        let proven_height = full_node_http_client
            .get_last_proven_l2_height()
            .await?
            .unwrap();

        // Proven height should match the committed height
        assert_eq!(proven_height.height, committed_height.height);
        assert_eq!(
            proven_height.commitment_index,
            committed_height.commitment_index
        );

        let status_at_proof_l1_height = full_node
            .client
            .http_client()
            .get_l2_status_heights_by_l1_height(batch_proof_l1_height)
            .await?;
        assert_eq!(
            status_at_proof_l1_height.committed.height,
            max_l2_blocks_per_commitment
        );
        assert_eq!(
            status_at_proof_l1_height.proven.height,
            max_l2_blocks_per_commitment
        );

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let second_commitment_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(second_commitment_l1_height, None)
            .await?;

        let committed_height2 = full_node_http_client
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        assert_eq!(committed_height2.height, max_l2_blocks_per_commitment * 2);
        assert_eq!(committed_height2.commitment_index, 2);

        // Proven height should still be at the first commitment
        let proven_height2 = full_node_http_client
            .get_last_proven_l2_height()
            .await?
            .unwrap();

        assert_eq!(proven_height2.height, max_l2_blocks_per_commitment);
        assert_eq!(proven_height2.commitment_index, 1);

        // Try a future non-existent L1 height
        let future_l1_height = second_commitment_l1_height + 1_000;
        let status = full_node
            .client
            .http_client()
            .get_l2_status_heights_by_l1_height(future_l1_height)
            .await?;
        assert_eq!(status.committed.height, max_l2_blocks_per_commitment * 2);
        assert_eq!(status.proven.height, max_l2_blocks_per_commitment);

        let status_at_commitment_l1_height = full_node_http_client
            .get_l2_status_heights_by_l1_height(commitment_l1_height)
            .await?;
        assert_eq!(
            status_at_commitment_l1_height.committed.height,
            max_l2_blocks_per_commitment
        );
        assert_eq!(status_at_commitment_l1_height.proven.height, 0);

        full_node.wait_until_stopped().await?;

        // Rollback to genesis and check that committed and proven height are correctly reset
        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "full-node",
                    "--db-path",
                    full_node.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    "0",
                    "--l1-target",
                    &f.initial_da_height.to_string(),
                    "--sequencer-commitment-index",
                    "0",
                ],
            )
            .await?;

        full_node.start(None, None).await?;

        let proven_height = full_node_http_client.get_last_proven_l2_height().await?;

        assert!(proven_height.is_none());

        let committed_height = full_node_http_client.get_last_committed_l2_height().await?;

        assert!(committed_height.is_none());

        let status_after_rollback = full_node
            .client
            .http_client()
            .get_l2_status_heights_by_l1_height(0)
            .await?;
        assert_eq!(status_after_rollback.committed.height, 0);
        assert_eq!(status_after_rollback.proven.height, 0);

        Ok(())
    }
}

#[tokio::test]
async fn test_l2_status_heights() -> Result<()> {
    TestCaseRunner::new(L2StatusTest)
        .set_citrea_path(get_citrea_path())
        .set_citrea_cli_path(get_citrea_cli_path())
        .run()
        .await
}

struct OutOfOrderCommitmentsTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for OutOfOrderCommitmentsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            // Extra args required for dropping wallet txs on bitcoin restart
            extra_args: vec!["-persistmempool=0", "-walletbroadcast=0"],
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let task_executor = self.task_manager.executor();

        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            task_executor,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        for _ in 0..max_l2_blocks_per_commitment * 2 {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(4, None).await?;

        let range1 = sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), U64::from(max_l2_blocks_per_commitment))
            .await?;

        let merkle_root1 = calculate_merkle_root(&range1);

        let range2 = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(max_l2_blocks_per_commitment + 1),
                U64::from(max_l2_blocks_per_commitment * 2),
            )
            .await?;

        let merkle_root2 = calculate_merkle_root(&range2);

        let first_commitment = SequencerCommitment {
            merkle_root: merkle_root1,
            l2_end_block_number: max_l2_blocks_per_commitment,
            index: 1,
        };

        let second_commitment = SequencerCommitment {
            merkle_root: merkle_root2,
            l2_end_block_number: max_l2_blocks_per_commitment * 2,
            index: 2,
        };

        let zero_index_commitment = SequencerCommitment {
            merkle_root: merkle_root1,
            l2_end_block_number: max_l2_blocks_per_commitment,
            index: 0,
        };

        // Restart and remove txs from mempool
        da.restart(None, None).await?;
        let mempool = da.get_raw_mempool().await?;
        assert_eq!(mempool.len(), 0, "Mempool should be empty after restart");

        // Send the zero index commitment first, should be ignored
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(zero_index_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let second_batch_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(second_batch_height, None)
            .await?;

        // Check that zero index commitment is succesfully skipped
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?;
        assert!(committed_height.is_none());

        // Send the second commitment first
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(second_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let second_batch_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(second_batch_height, None)
            .await?;

        // Check out of order processing
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?;
        // Assert that out of order commitment hasn't been processed
        assert!(committed_height.is_none());

        // Send the first commitment
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(first_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(finalized_height, None).await?;
        // Process out of order seq on following block
        da.generate(1).await?;
        full_node
            .wait_for_l1_height(finalized_height + 1, None)
            .await?;

        let final_committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        // Assert that pending commitments were processed
        assert_eq!(
            final_committed_height.height,
            max_l2_blocks_per_commitment * 2
        );
        assert_eq!(final_committed_height.commitment_index, 2);

        Ok(())
    }
}

#[tokio::test]
async fn test_out_of_order_commitments() -> Result<()> {
    TestCaseRunner::new(OutOfOrderCommitmentsTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct ConflictingCommitmentsTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for ConflictingCommitmentsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_sequencer: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-persistmempool=0", "-walletbroadcast=0"],
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let task_executor = self.task_manager.executor();

        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            task_executor,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;

        // Restart and remove txs from mempool
        da.restart(None, None).await?;
        assert_eq!(
            da.get_raw_mempool().await?.len(),
            0,
            "Mempool should be empty"
        );

        let range1 = sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), U64::from(max_l2_blocks_per_commitment))
            .await?;

        let correct_merkle_root = calculate_merkle_root(&range1);
        let commitment_a = SequencerCommitment {
            merkle_root: correct_merkle_root,
            l2_end_block_number: max_l2_blocks_per_commitment,
            index: 1,
        };

        // Create another conflicting commitment B with same index but different l2_end_block_number
        let commitment_b = SequencerCommitment {
            merkle_root: correct_merkle_root,
            l2_end_block_number: max_l2_blocks_per_commitment - 1,
            index: 1,
        };

        // Create another conflicting commitment B with same index but different merkle root
        let conflicting_commitment_different_root = SequencerCommitment {
            merkle_root: [1u8; 32],
            l2_end_block_number: max_l2_blocks_per_commitment,
            index: 1,
        };

        // Send commitment A
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment_a.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height_a = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(l1_height_a, None).await?;

        // Assert that commitment A was processed
        let committed_height_a = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        assert_eq!(committed_height_a.height, max_l2_blocks_per_commitment);
        assert_eq!(committed_height_a.commitment_index, 1);

        // Send conflicting commitment with different merkle root, should be ignored
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(conflicting_commitment_different_root.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height_b = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(l1_height_b, None).await?;

        // The full node should ignore commitment with conflicting merkle root
        let committed_height_b = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        // The committed height should still match commitment A
        assert_eq!(committed_height_b.height, max_l2_blocks_per_commitment);
        assert_eq!(committed_height_b.commitment_index, 1);

        // Send conflicting commitment B
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment_b.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height_b = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(l1_height_b, None).await?;

        // The full node should ignore second commitment with conflicting index
        let committed_height_b = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        // The committed height should still match commitment A
        assert_eq!(committed_height_b.height, max_l2_blocks_per_commitment);
        assert_eq!(committed_height_b.commitment_index, 1);

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;

        let range2 = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(max_l2_blocks_per_commitment + 1),
                U64::from(max_l2_blocks_per_commitment * 2),
            )
            .await?;

        let merkle_root2 = calculate_merkle_root(&range2);
        let commitment_c = SequencerCommitment {
            merkle_root: merkle_root2,
            l2_end_block_number: max_l2_blocks_per_commitment * 2,
            index: 2,
        };

        // Send commitment C that follows A
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment_c.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height_c = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(l1_height_c, None).await?;

        // Check that commitment C is correctly handled and follows A
        let final_committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        assert_eq!(
            final_committed_height.height,
            max_l2_blocks_per_commitment * 2
        );
        assert_eq!(final_committed_height.commitment_index, 2);

        Ok(())
    }
}

#[tokio::test]
async fn test_conflicting_commitments() -> Result<()> {
    TestCaseRunner::new(ConflictingCommitmentsTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct OutOfRangeProofTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for OutOfRangeProofTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_sequencer: true,
            with_batch_prover: true,
            with_citrea_cli: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            // Extra args required for dropping wallet txs on bitcoin restart
            extra_args: vec!["-persistmempool=0", "-walletbroadcast=0"],
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let task_executor = self.task_manager.executor();

        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let citrea_cli = f.citrea_cli.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let prover_da_service = spawn_bitcoin_da_service(
            task_executor.clone(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        let sequencer_da_service = spawn_bitcoin_da_service(
            task_executor,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        // Generate two commitments to test pending proof over commitment ranges
        for _ in 0..max_l2_blocks_per_commitment * 2 {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitments_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(commitments_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        let range1 = sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), U64::from(max_l2_blocks_per_commitment))
            .await?;
        let merkle_root1 = calculate_merkle_root(&range1);
        let commitment1 = SequencerCommitment {
            merkle_root: merkle_root1,
            l2_end_block_number: max_l2_blocks_per_commitment,
            index: 1,
        };

        let range2 = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(max_l2_blocks_per_commitment + 1),
                U64::from(max_l2_blocks_per_commitment * 2),
            )
            .await?;
        let merkle_root2 = calculate_merkle_root(&range2);
        let commitment2 = SequencerCommitment {
            merkle_root: merkle_root2,
            l2_end_block_number: max_l2_blocks_per_commitment * 2,
            index: 2,
        };

        let proof1 = wait_for_zkproofs(full_node, proof_l1_height, None, 1)
            .await
            .unwrap()[0]
            .clone()
            .proof;

        // Generate a third commitment for second proof
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitments_l1_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(commitments_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        let range3 = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(max_l2_blocks_per_commitment * 2 + 1),
                U64::from(max_l2_blocks_per_commitment * 3),
            )
            .await?;
        let merkle_root3 = calculate_merkle_root(&range3);
        let commitment3 = SequencerCommitment {
            merkle_root: merkle_root3,
            l2_end_block_number: max_l2_blocks_per_commitment * 3,
            index: 3,
        };

        let proof2 = wait_for_zkproofs(full_node, proof_l1_height, None, 1)
            .await
            .unwrap()[0]
            .clone()
            .proof;

        // Generate a fourth commitment for third proof
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitments_l1_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(commitments_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        let range4 = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(max_l2_blocks_per_commitment * 3 + 1),
                U64::from(max_l2_blocks_per_commitment * 4),
            )
            .await?;
        let merkle_root4 = calculate_merkle_root(&range4);
        let commitment4 = SequencerCommitment {
            merkle_root: merkle_root4,
            l2_end_block_number: max_l2_blocks_per_commitment * 4,
            index: 4,
        };

        let proof3 = wait_for_zkproofs(full_node, proof_l1_height, None, 1)
            .await
            .unwrap()[0]
            .clone()
            .proof;

        /*
         ** Test that a proof is discarded if it's over a range of sequencer commitment that hasn't been processed yet
         ** Send proof first then the two commitments in order.
         */
        // Rollback bitcoin to initial height and drop existing txs so that we can re-send them out of order
        let initial_height_hash = da.get_block_hash(f.initial_da_height + 1).await?;
        da.invalidate_block(&initial_height_hash).await?;
        let block_count = da.get_block_count().await?;
        assert_eq!(block_count, f.initial_da_height);
        // Restart and remove rolledback txs from mempool
        da.restart(None, None).await?;
        assert_eq!(
            da.get_raw_mempool().await?.len(),
            0,
            "Mempool should be empty"
        );

        // Rollback full node to genesis
        full_node.wait_until_stopped().await?;
        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "full-node",
                    "--db-path",
                    full_node.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    "0",
                    "--l1-target",
                    &f.initial_da_height.to_string(),
                    "--sequencer-commitment-index",
                    "0",
                ],
            )
            .await?;

        full_node.start(None, None).await?;

        // Send the proof first. It should be discard as none of its commitments exist
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(proof1.clone()), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        // The proof should be discarded and not be processed
        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?;
        assert!(
            proven_height.is_none(),
            "No proof should be processed without commitments"
        );

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment1.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment1_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(commitment1_l1_height, None)
            .await?;

        // The first commitment should be processed and no proof should be pending
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(committed_height.height, max_l2_blocks_per_commitment);
        assert_eq!(committed_height.commitment_index, 1);

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?;
        assert!(proven_height.is_none(), "Proof should have been discarded");

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment2.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment2_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(commitment2_l1_height, None)
            .await?;

        // Both commitments should be processed and make sure the proof was discarded
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(committed_height.height, max_l2_blocks_per_commitment * 2);
        assert_eq!(committed_height.commitment_index, 2);

        // Make sure proof was discarded even after processing its commitment range
        // It was discarded as at the time of proof processing, the commitment range wasn't valid
        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?;
        assert!(proven_height.is_none(), "Proof should have been discarded");

        /*
         ** Test that a proof is discarded if it's starting
         ** Send the the two first commitments in order then send the first proof. It should be processed and valid over the range commitment range [1, 2].
         ** Then send third proof over range [4] (missing proof over range 3) that should be left pending.
         ** Then send second proof over range [3] that should be processed and then trigger a processing of pending third proof
         */

        // Rollback bitcoin to initial height and drop existing txs so that we can re-send them out of order
        let initial_height_hash = da.get_block_hash(f.initial_da_height + 1).await?;
        da.invalidate_block(&initial_height_hash).await?;
        let block_count = da.get_block_count().await?;
        assert_eq!(block_count, f.initial_da_height);
        // Restart and remove rolledback txs from mempool
        da.restart(None, None).await?;
        assert_eq!(
            da.get_raw_mempool().await?.len(),
            0,
            "Mempool should be empty"
        );

        // Rollback full node to genesis
        full_node.wait_until_stopped().await?;
        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "full-node",
                    "--db-path",
                    full_node.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    "0",
                    "--l1-target",
                    &f.initial_da_height.to_string(),
                    "--sequencer-commitment-index",
                    "0",
                ],
            )
            .await?;

        full_node.start(None, None).await?;

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment1.clone()),
                1,
            )
            .await
            .unwrap();

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment2.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment2_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(commitment2_l1_height, None)
            .await?;

        // Both commitments should be processed
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(committed_height.height, max_l2_blocks_per_commitment * 2);
        assert_eq!(committed_height.commitment_index, 2);

        // Send the proof first. It should be processed as its commitments exist
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(proof1), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        // The proof should have been processed
        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();

        assert_eq!(proven_height.height, max_l2_blocks_per_commitment * 2);
        assert_eq!(proven_height.commitment_index, 2);

        // Send commitments for proof 2 and proof 3
        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment3.clone()),
                1,
            )
            .await
            .unwrap();

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment4.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment2_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(commitment2_l1_height, None)
            .await?;

        // Both commitments should be processed
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(committed_height.height, max_l2_blocks_per_commitment * 4);
        assert_eq!(committed_height.commitment_index, 4);

        // Send the third proof first. It should be set as pending as its commitments exist but it's starting commitment index is not proven proof last commitment index + 1
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(proof3), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        // The proof should be pending
        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();

        assert_eq!(proven_height.height, max_l2_blocks_per_commitment * 2);
        assert_eq!(proven_height.commitment_index, 2);

        // Now send the second proof. It should be processed and trigger a processing of pending proof3
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(proof2), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        // All proofs should have been processed
        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();

        assert_eq!(proven_height.height, max_l2_blocks_per_commitment * 4);
        assert_eq!(proven_height.commitment_index, 4);

        Ok(())
    }
}

#[tokio::test]
async fn test_out_of_range_proof() -> Result<()> {
    TestCaseRunner::new(OutOfRangeProofTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .set_citrea_cli_path(get_citrea_cli_path())
    .run()
    .await
}

struct OverlappingProofRangesTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for OverlappingProofRangesTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_sequencer: true,
            with_batch_prover: true,
            with_citrea_cli: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-persistmempool=0", "-walletbroadcast=0"],
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let task_executor = self.task_manager.executor();

        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_mut().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let citrea_cli = f.citrea_cli.as_ref().unwrap();

        let sequencer_da_service = spawn_bitcoin_da_service(
            task_executor.clone(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        let prover_da_service = spawn_bitcoin_da_service(
            task_executor,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        // Generate 3 commitments
        for _ in 0..max_l2_blocks_per_commitment * 3 {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(6, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitments_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(commitments_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        // Extract proof_a over range [1,2,3]
        let proof_a = wait_for_zkproofs(full_node, proof_l1_height, None, 1)
            .await
            .unwrap()[0]
            .clone()
            .proof;

        let range1 = sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), U64::from(max_l2_blocks_per_commitment))
            .await?;
        let merkle_root1 = calculate_merkle_root(&range1);

        let range2 = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(max_l2_blocks_per_commitment + 1),
                U64::from(max_l2_blocks_per_commitment * 2),
            )
            .await?;
        let merkle_root2 = calculate_merkle_root(&range2);

        let range3 = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(max_l2_blocks_per_commitment * 2 + 1),
                U64::from(max_l2_blocks_per_commitment * 3),
            )
            .await?;
        let merkle_root3 = calculate_merkle_root(&range3);

        let commitment1 = SequencerCommitment {
            merkle_root: merkle_root1,
            l2_end_block_number: max_l2_blocks_per_commitment,
            index: 1,
        };

        let commitment2 = SequencerCommitment {
            merkle_root: merkle_root2,
            l2_end_block_number: max_l2_blocks_per_commitment * 2,
            index: 2,
        };

        let commitment3 = SequencerCommitment {
            merkle_root: merkle_root3,
            l2_end_block_number: max_l2_blocks_per_commitment * 3,
            index: 3,
        };

        // Rollback Bitcoin to initial height
        let initial_height_hash = da.get_block_hash(f.initial_da_height + 1).await?;
        da.invalidate_block(&initial_height_hash).await?;
        let block_count = da.get_block_count().await?;
        assert_eq!(block_count, f.initial_da_height);
        da.restart(None, None).await?;
        assert_eq!(
            da.get_raw_mempool().await?.len(),
            0,
            "Mempool should be empty"
        );

        // Rollback fullnode to genesis
        full_node.wait_until_stopped().await?;
        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "full-node",
                    "--db-path",
                    full_node.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    "0",
                    "--l1-target",
                    &f.initial_da_height.to_string(),
                    "--sequencer-commitment-index",
                    "0",
                ],
            )
            .await?;

        full_node.start(None, None).await?;

        // Rollback batchprover to genesis
        batch_prover.wait_until_stopped().await?;
        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "batch-prover",
                    "--db-path",
                    batch_prover.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    "0",
                    "--l1-target",
                    &f.initial_da_height.to_string(),
                    "--sequencer-commitment-index",
                    "0",
                ],
            )
            .await?;

        batch_prover.start(None, None).await?;

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment1.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(commitment_l1_height, None)
            .await?;

        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(committed_height.height, max_l2_blocks_per_commitment);
        assert_eq!(committed_height.commitment_index, 1);

        let commitments_l1_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(commitments_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        // Generate a proof over commitment range [1] that will be discarded
        let _discarded_proof = wait_for_zkproofs(full_node, proof_l1_height, None, 1)
            .await
            .unwrap()[0]
            .clone()
            .proof;

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment2.clone()),
                1,
            )
            .await
            .unwrap();

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment3.clone()),
                1,
            )
            .await
            .unwrap();

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        da.wait_mempool_len(6, None).await?;

        let range4 = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(max_l2_blocks_per_commitment * 3 + 1),
                U64::from(max_l2_blocks_per_commitment * 4),
            )
            .await?;
        let merkle_root4 = calculate_merkle_root(&range4);

        let commitment4 = SequencerCommitment {
            merkle_root: merkle_root4,
            l2_end_block_number: max_l2_blocks_per_commitment * 4,
            index: 4,
        };

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitments_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(commitments_l1_height, None)
            .await?;

        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(committed_height.height, max_l2_blocks_per_commitment * 4);
        assert_eq!(committed_height.commitment_index, 4);

        // Generate a proof over range [2,3,4]
        batch_prover
            .wait_for_l1_height(commitments_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_b_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(proof_b_l1_height, None)
            .await?;

        // Extract proof_b over range [2,3,4]
        let proof_b = wait_for_zkproofs(full_node, proof_b_l1_height, None, 1)
            .await
            .unwrap()[0]
            .clone()
            .proof;

        // Rollback Bitcoin to initial height and clear transactions
        let initial_height_hash = da.get_block_hash(f.initial_da_height + 1).await?;
        da.invalidate_block(&initial_height_hash).await?;
        let block_count = da.get_block_count().await?;
        assert_eq!(block_count, f.initial_da_height);

        // Restart Bitcoin node and clear mempool
        da.restart(None, None).await?;
        assert_eq!(
            da.get_raw_mempool().await?.len(),
            0,
            "Mempool should be empty"
        );

        // Rollback fullnode to genesis
        full_node.wait_until_stopped().await?;
        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "full-node",
                    "--db-path",
                    full_node.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    "0",
                    "--l1-target",
                    &f.initial_da_height.to_string(),
                    "--sequencer-commitment-index",
                    "0",
                ],
            )
            .await?;

        full_node.start(None, None).await?;

        // Send all 4 commitments in order
        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment1.clone()),
                1,
            )
            .await
            .unwrap();

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment2.clone()),
                1,
            )
            .await
            .unwrap();

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment3.clone()),
                1,
            )
            .await
            .unwrap();

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment4.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(8, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitments_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(commitments_l1_height, None)
            .await?;

        // Check that all commitments were processed
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(committed_height.height, max_l2_blocks_per_commitment * 4);
        assert_eq!(committed_height.commitment_index, 4);

        // Send proof_a over commitments [1,2,3]
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(proof_a.clone()), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_a_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(proof_a_l1_height, None)
            .await?;

        let proof_output_a = wait_for_zkproofs(full_node, proof_a_l1_height, None, 1)
            .await
            .unwrap()[0]
            .clone()
            .proof_output;
        assert_eq!(
            proof_output_a
                .sequencer_commitment_index_range
                .0
                .to::<u32>(),
            1
        );
        assert_eq!(
            proof_output_a
                .sequencer_commitment_index_range
                .1
                .to::<u32>(),
            3
        );

        // Assert that proof was processed
        let proven_height_a = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(proven_height_a.height, max_l2_blocks_per_commitment * 3);
        assert_eq!(proven_height_a.commitment_index, 3);

        // Send proof_b with overlapping range of [2,3,4]
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(proof_b.clone()), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_b_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(proof_b_l1_height, None)
            .await?;

        let proof_output_b = wait_for_zkproofs(full_node, proof_b_l1_height, None, 1)
            .await
            .unwrap()[0]
            .clone()
            .proof_output;
        assert_eq!(
            proof_output_b
                .sequencer_commitment_index_range
                .0
                .to::<u32>(),
            2
        );
        assert_eq!(
            proof_output_b
                .sequencer_commitment_index_range
                .1
                .to::<u32>(),
            4
        );

        // Verify second proof was processed and proven height is now at index 4
        let proven_height_b = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(proven_height_b.height, max_l2_blocks_per_commitment * 4);
        assert_eq!(proven_height_b.commitment_index, 4);

        Ok(())
    }
}

#[tokio::test]
async fn test_overlapping_proof_ranges() -> Result<()> {
    TestCaseRunner::new(OverlappingProofRangesTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .set_citrea_cli_path(get_citrea_cli_path())
    .run()
    .await
}

struct UnsyncedCommitmentL2RangeTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for UnsyncedCommitmentL2RangeTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-persistmempool=0", "-walletbroadcast=0"],
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        /*
        Sequencer max l2 blocks is 10000 so it does not publish commitments
        Sequencer publish 1-10
        Full node sync 1-10
        Stop full node
        Sequencer publish 11-30
        Create commitments 1-3
        Prover create proof over range [1]
        Prover create proof over range [2]
        Prover create proof over range [3]
        Get all proofs from prover
        Stop prover
        Stop sequencer (so full node can't sync)
        Start full node
        Full node will get all the commitments and proofs
        Assert only the first proof is valid
        Assert the committed and proven heights
        Start Sequencer
        Sync full node
        Assert the committed and proven heights
        They should be the latest ones

         */
        let task_executor = self.task_manager.executor();

        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();
        let batch_prover = f.batch_prover.as_mut().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let light_client_prover = f.light_client_prover.as_mut().unwrap();

        let sequencer_da_service = spawn_bitcoin_da_service(
            task_executor.clone(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        let sequencer_client = sequencer.client.clone();

        for _ in 1..=10 {
            sequencer_client.send_publish_batch_request().await?;
        }
        sequencer_client.wait_for_l2_block(10, None).await?;

        full_node.wait_for_l2_height(10, None).await?;
        full_node.wait_until_stopped().await?;

        for _ in 11..=30 {
            sequencer_client.send_publish_batch_request().await?;
        }

        sequencer_client.wait_for_l2_block(30, None).await?;

        let l2_range_blocks = sequencer_client
            .http_client()
            .get_l2_block_range(U64::from(1), U64::from(10))
            .await?;

        let merkle_root_1 = calculate_merkle_root(&l2_range_blocks);

        let l2_range_blocks = sequencer_client
            .http_client()
            .get_l2_block_range(U64::from(11), U64::from(20))
            .await?;

        let merkle_root_2 = calculate_merkle_root(&l2_range_blocks);

        let l2_range_blocks = sequencer_client
            .http_client()
            .get_l2_block_range(U64::from(21), U64::from(30))
            .await?;

        let merkle_root_3 = calculate_merkle_root(&l2_range_blocks);

        let commitment_1 = SequencerCommitment {
            merkle_root: merkle_root_1,
            l2_end_block_number: 10,
            index: 1,
        };
        let commitment_2 = SequencerCommitment {
            merkle_root: merkle_root_2,
            l2_end_block_number: 20,
            index: 2,
        };
        let commitment_3 = SequencerCommitment {
            merkle_root: merkle_root_3,
            l2_end_block_number: 30,
            index: 3,
        };

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment_1.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitments_1_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(commitments_1_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_1_l1_height = da.get_finalized_height(None).await?;

        // Wait for proving job to start
        let job_ids = wait_for_prover_job_count(batch_prover, 1, None)
            .await
            .unwrap();
        assert_eq!(job_ids.len(), 1);
        let job_id = job_ids[0];

        // Wait for proving job to finish
        let response = wait_for_prover_job(batch_prover, job_id, None)
            .await
            .unwrap();

        assert_eq!(
            response
                .proof
                .clone()
                .unwrap()
                .proof_output
                .sequencer_commitment_index_range,
            (U32::from(1), U32::from(1))
        );
        // Extract proof_a over range [1]
        let _proof_a = response.proof.unwrap().proof;

        /*------- */

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment_2.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitments_2_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(commitments_2_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_2_l1_height = da.get_finalized_height(None).await?;

        let job_ids = wait_for_prover_job_count(batch_prover, 1, None)
            .await
            .unwrap();
        assert_eq!(job_ids.len(), 1);
        let job_id = job_ids[0];

        // Wait for proving job to finish
        let response = wait_for_prover_job(batch_prover, job_id, None)
            .await
            .unwrap();

        assert_eq!(
            response
                .proof
                .clone()
                .unwrap()
                .proof_output
                .sequencer_commitment_index_range,
            (U32::from(2), U32::from(2))
        );
        // Extract proof_b over range [2]
        let _proof_b = response.proof.unwrap().proof;

        /*------- */

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment_3.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitments_3_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(commitments_3_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_3_l1_height = da.get_finalized_height(None).await?;

        let job_ids = wait_for_prover_job_count(batch_prover, 1, None)
            .await
            .unwrap();
        assert_eq!(job_ids.len(), 1);
        let job_id = job_ids[0];

        // Wait for proving job to finish
        let response = wait_for_prover_job(batch_prover, job_id, None)
            .await
            .unwrap();
        assert_eq!(
            response
                .proof
                .clone()
                .unwrap()
                .proof_output
                .sequencer_commitment_index_range,
            (U32::from(3), U32::from(3))
        );
        // Extract proof_c over range [3]
        let _proof_c = response.proof.unwrap().proof;

        // We are done with batch prover
        batch_prover.wait_until_stopped().await?;

        // Stop sequencer for now
        sequencer.wait_until_stopped().await?;

        let finalized_height = da.get_finalized_height(None).await?;

        // Start full node
        full_node.start(None, None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;

        // Check that the first commitment was processed
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(committed_height.height, commitment_1.l2_end_block_number);
        assert_eq!(committed_height.commitment_index, 1);

        // Check that the first proof was processed
        let proof_output_1 = wait_for_zkproofs(full_node, proof_1_l1_height, None, 1)
            .await
            .unwrap()[0]
            .clone()
            .proof_output;
        assert_eq!(
            proof_output_1
                .sequencer_commitment_index_range
                .0
                .to::<u32>(),
            1
        );
        assert_eq!(
            proof_output_1
                .sequencer_commitment_index_range
                .1
                .to::<u32>(),
            1
        );
        // Check the proven height and index
        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(proven_height.height, commitment_1.l2_end_block_number);
        assert_eq!(proven_height.commitment_index, 1);

        // Start the sequencer so the full node can sync
        sequencer.start(None, None).await?;

        full_node
            .wait_for_l2_height(commitment_3.l2_end_block_number, None)
            .await?;

        // Process one l1 block to trigger pending commitment and pending proof processing
        da.generate(1).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;

        // The proofs should have been processed now
        let proof_output_2 = wait_for_zkproofs(full_node, proof_2_l1_height, None, 1)
            .await
            .unwrap();

        assert!(proof_output_2.len() == 1);

        assert_eq!(
            proof_output_2[0]
                .clone()
                .proof_output
                .sequencer_commitment_index_range,
            (U32::from(2), U32::from(2))
        );

        // The proofs should have been processed now
        let proof_output_3 = wait_for_zkproofs(full_node, proof_3_l1_height, None, 1)
            .await
            .unwrap();

        assert!(proof_output_3.len() == 1);

        assert_eq!(
            proof_output_3[0]
                .clone()
                .proof_output
                .sequencer_commitment_index_range,
            (U32::from(3), U32::from(3))
        );

        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        // Assert that the last committed height is now at the last commitment
        assert_eq!(committed_height.height, commitment_3.l2_end_block_number);

        // Assert that the last proven height is now at the last commitment
        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(proven_height.height, commitment_3.l2_end_block_number);
        assert_eq!(proven_height.commitment_index, 3);

        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?
            .unwrap();
        assert_eq!(
            lcp.light_client_proof_output.last_l2_height,
            U64::from(committed_height.height)
        );
        assert_eq!(
            lcp.light_client_proof_output
                .last_sequencer_commitment_index,
            U32::from(committed_height.commitment_index)
        );
        assert_eq!(
            lcp.light_client_proof_output.last_l2_height,
            U64::from(proven_height.height)
        );
        assert_eq!(
            lcp.light_client_proof_output
                .last_sequencer_commitment_index,
            U32::from(proven_height.commitment_index)
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_unsynced_commitment_l2_range_test() -> Result<()> {
    TestCaseRunner::new(UnsyncedCommitmentL2RangeTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .set_citrea_cli_path(get_citrea_cli_path())
    .run()
    .await
}

struct FullNodeLcpChunkProofTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for FullNodeLcpChunkProofTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_sequencer: true,
            with_light_client_prover: true,
            with_batch_prover: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec![
                "-persistmempool=0",
                "-walletbroadcast=0",
                "-fallbackfee=0.00001",
            ],
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            // prevent proving
            proof_sampling_number: 999_999_999_999,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        /*
        Sequencer max l2 blocks is 10000 so it does not publish commitments
        Sequencer publish 1-40
        Full node sync 1-40
        Stop full node
        Sequencer publish 1-10, 11-20, 21-30, 31-40
        Create commitments 1..4
        create fake proof over range [1,2] with 2 chunks
        send to da
        mine them in correct order chunk1 - chunk2 - aggregate
        see the same results in lcp and full node
        create fake proof over range [3,4] with 2 chunks
        send to da
        mine them with wrong order chunk1 - aggregate - chunk2
        see that both full node and lcp did not process that proof
        create fake proof over range [3,4] with 2 chunks
        mine chunk 1 to block n
        mine chunk 2 to block n+1
        mine aggregate to block n+2
        see that both full node and lcp processes the proof
        create fake proof over range [5,6] with 2 chunks
        mine chunk 1 to block m
        mine aggregate to block m+1
        mine chunk 2 to block m+2
        see that because the order is wrong the proof is not processed for both lcp and full node
         */
        let task_executor = self.task_manager.executor();

        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();
        let _batch_prover = f.batch_prover.as_mut().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let light_client_prover = f.light_client_prover.as_mut().unwrap();

        let batch_prover_da_service = spawn_bitcoin_da_service(
            task_executor,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to create light client proof.
        light_client_prover
            .wait_for_l1_height(finalized_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;

        // Get initial method ids and genesis state root
        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        let genesis_state_root = lcp_output.l2_state_root;

        let sequencer_client = sequencer.client.clone();

        for _ in 1..=60 {
            sequencer_client.send_publish_batch_request().await?;
        }
        sequencer_client.wait_for_l2_block(60, None).await?;
        full_node.wait_for_l2_height(60, None).await?;

        // Wait for 6 sequencer commitments
        da.wait_mempool_len(12, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for full node to process sequencer commitments
        full_node.wait_for_l1_height(finalized_height, None).await?;

        let commitment_1 = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(1))
            .await?
            .map(|c| SequencerCommitment {
                merkle_root: c.merkle_root,
                l2_end_block_number: c.l2_end_block_number.to::<u64>(),
                index: c.index.to::<u32>(),
            })
            .unwrap();
        let commitment_1_state_root = sequencer_client
            .http_client()
            .get_l2_block_by_number(U64::from(commitment_1.l2_end_block_number))
            .await?
            .unwrap()
            .header
            .state_root;
        let commitment_2 = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(2))
            .await?
            .map(|c| SequencerCommitment {
                merkle_root: c.merkle_root,
                l2_end_block_number: c.l2_end_block_number.to::<u64>(),
                index: c.index.to::<u32>(),
            })
            .unwrap();
        let commitment_2_state_root = sequencer_client
            .http_client()
            .get_l2_block_by_number(U64::from(commitment_2.l2_end_block_number))
            .await?
            .unwrap()
            .header
            .state_root;
        let commitment_3 = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(3))
            .await?
            .map(|c| SequencerCommitment {
                merkle_root: c.merkle_root,
                l2_end_block_number: c.l2_end_block_number.to::<u64>(),
                index: c.index.to::<u32>(),
            })
            .unwrap();
        let commitment_3_state_root = sequencer_client
            .http_client()
            .get_l2_block_by_number(U64::from(commitment_3.l2_end_block_number))
            .await?
            .unwrap()
            .header
            .state_root;
        let commitment_4 = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(4))
            .await?
            .map(|c| SequencerCommitment {
                merkle_root: c.merkle_root,
                l2_end_block_number: c.l2_end_block_number.to::<u64>(),
                index: c.index.to::<u32>(),
            })
            .unwrap();
        let commitment_4_state_root = sequencer_client
            .http_client()
            .get_l2_block_by_number(U64::from(commitment_4.l2_end_block_number))
            .await?
            .unwrap()
            .header
            .state_root;
        let commitment_5 = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(5))
            .await?
            .map(|c| SequencerCommitment {
                merkle_root: c.merkle_root,
                l2_end_block_number: c.l2_end_block_number.to::<u64>(),
                index: c.index.to::<u32>(),
            })
            .unwrap();
        let commitment_5_state_root = sequencer_client
            .http_client()
            .get_l2_block_by_number(U64::from(commitment_5.l2_end_block_number))
            .await?
            .unwrap()
            .header
            .state_root;
        let commitment_6 = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(6))
            .await?
            .map(|c| SequencerCommitment {
                merkle_root: c.merkle_root,
                l2_end_block_number: c.l2_end_block_number.to::<u64>(),
                index: c.index.to::<u32>(),
            })
            .unwrap();
        let commitment_6_state_root = sequencer_client
            .http_client()
            .get_l2_block_by_number(U64::from(commitment_6.l2_end_block_number))
            .await?
            .unwrap()
            .header
            .state_root;

        let state_diff_60kb = create_random_state_diff(60);

        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 60kb (compressed size) batch proof (not 1mb because if testing feature is enabled max body size is 39700), this batch proof will consist of 2 chunks and 1 aggregate transactions because 60kb/40kb = 2 chunks
        let verifiable_60kb_batch_proof =
            create_serialized_fake_receipt_batch_proof_with_state_roots(
                genesis_state_root,
                20,
                batch_proof_method_ids[0].method_id.into(),
                Some(state_diff_60kb.clone()),
                false,
                l1_hash.as_raw_hash().to_byte_array(),
                vec![commitment_1.clone(), commitment_2.clone()],
                vec![commitment_1_state_root, commitment_2_state_root],
                None,
            );

        let _ = batch_prover_da_service
            .test_send_separate_chunk_transaction_with_fee_rate(
                DaTxRequest::ZKProof(verifiable_60kb_batch_proof),
                1,
            )
            .await
            .unwrap();

        // In total 2 chunks 1 aggregate with all of them having reveal and commit txs we should have 6 txs in mempool
        da.wait_mempool_len(6, Some(TEN_MINS)).await?;

        let txs = da.get_raw_mempool().await?;
        assert_eq!(txs.len(), 6);

        let mut reveals = vec![Txid::all_zeros(), Txid::all_zeros(), Txid::all_zeros()];

        let mut commits = Vec::with_capacity(3);

        for txid in txs {
            let tx = da
                .get_transaction(&txid, None)
                .await?
                .transaction()
                .unwrap();

            let parsed = parse_relevant_transaction(&tx);
            match parsed {
                Ok(ParsedTransaction::Aggregate(_)) => {
                    // Make sure the aggregate tx is the last one
                    reveals[2] = txid;
                }
                Ok(ParsedTransaction::Chunk(_)) => {
                    if reveals[0] == Txid::all_zeros() {
                        reveals[0] = txid;
                    } else if reveals[1] == Txid::all_zeros() {
                        reveals[1] = txid;
                    }
                }
                Err(_) => commits.push(txid),
                _ => {}
            }
        }

        // Make sure commits are before reveals
        commits.extend(reveals);
        let tx_ids_in_order = commits.clone();

        let addr = da
            .get_new_address(None, None)
            .await?
            .assume_checked()
            .to_string();
        da.generate_block(
            addr,
            tx_ids_in_order.iter().map(|tx| tx.to_string()).collect(),
        )
        .await?;

        da.generate(DEFAULT_FINALITY_DEPTH - 1).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for full node to process proofs
        full_node.wait_for_l1_height(finalized_height, None).await?;
        // Wait for lcp to process proofs
        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Check that the proof was processed
        let last_proven_l2_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(last_proven_l2_height.height, 20);
        assert_eq!(last_proven_l2_height.commitment_index, 2);

        // Expect the same results in lcp
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;
        assert_eq!(
            lcp_output.last_l2_height,
            U64::from(last_proven_l2_height.height)
        );
        assert_eq!(
            lcp_output.last_sequencer_commitment_index,
            U32::from(last_proven_l2_height.commitment_index)
        );

        let last_state_root = lcp_output.l2_state_root;

        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 60kb (compressed size) batch proof this batch proof will consist of 2 chunks and 1 aggregate transactions because 60kb/40kb = 2 chunks
        let verifiable_60kb_batch_proof =
            create_serialized_fake_receipt_batch_proof_with_state_roots(
                last_state_root,
                40,
                batch_proof_method_ids[0].method_id.into(),
                Some(state_diff_60kb.clone()),
                false,
                l1_hash.as_raw_hash().to_byte_array(),
                vec![commitment_3.clone(), commitment_4.clone()],
                vec![commitment_3_state_root, commitment_4_state_root],
                Some(commitment_2.serialize_and_calculate_sha_256()),
            );

        let _ = batch_prover_da_service
            .test_send_separate_chunk_transaction_with_fee_rate(
                DaTxRequest::ZKProof(verifiable_60kb_batch_proof),
                1,
            )
            .await
            .unwrap();

        // In total 2 chunks 1 aggregate with all of them having reveal and commit txs we should have 6 txs in mempool
        da.wait_mempool_len(6, Some(TEN_MINS)).await?;

        let txs = da.get_raw_mempool().await?;
        assert_eq!(txs.len(), 6);

        let mut reveals = vec![Txid::all_zeros(), Txid::all_zeros(), Txid::all_zeros()];

        let mut commits = Vec::with_capacity(3);

        for txid in txs {
            let tx = da
                .get_transaction(&txid, None)
                .await?
                .transaction()
                .unwrap();

            let parsed = parse_relevant_transaction(&tx);
            match parsed {
                Ok(ParsedTransaction::Aggregate(_)) => {
                    // Make sure the aggregate tx is the last one
                    reveals[1] = txid;
                }
                Ok(ParsedTransaction::Chunk(_)) => {
                    if reveals[0] == Txid::all_zeros() {
                        reveals[0] = txid;
                        // Put one reveal in wrong order (after aggregate)
                    } else if reveals[2] == Txid::all_zeros() {
                        reveals[2] = txid;
                    }
                }
                Err(_) => commits.push(txid),
                _ => {}
            }
        }

        // Make sure commits are before reveals
        commits.extend(reveals);
        let tx_ids_in_wrong_order = commits.clone();

        let addr = da
            .get_new_address(None, None)
            .await?
            .assume_checked()
            .to_string();
        da.generate_block(
            addr.clone(),
            tx_ids_in_wrong_order
                .iter()
                .map(|tx| tx.to_string())
                .collect(),
        )
        .await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for full node to process proofs
        full_node.wait_for_l1_height(finalized_height, None).await?;

        // Wait for lcp to process proofs
        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Check that the proof was not processed and the last proven height is still the same
        let last_proven_l2_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(last_proven_l2_height.height, 20);
        assert_eq!(last_proven_l2_height.commitment_index, 2);

        // Expect the same results in lcp
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;
        assert_eq!(
            lcp_output.last_l2_height,
            U64::from(last_proven_l2_height.height)
        );
        assert_eq!(
            lcp_output.last_sequencer_commitment_index,
            U32::from(last_proven_l2_height.commitment_index)
        );

        let block_20_sr = sequencer_client
            .http_client()
            .get_l2_block_by_number(U64::from(20u64))
            .await?
            .unwrap()
            .header
            .state_root;

        // Test chunks are in previous l1 blocks of the aggregate and the proof is still valid because aggregate is the last one
        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 60kb (compressed size) batch proof this batch proof will consist of 2 chunks and 1 aggregate transactions because 60kb/40kb = 2 chunks
        let verifiable_60kb_batch_proof =
            create_serialized_fake_receipt_batch_proof_with_state_roots(
                block_20_sr,
                40,
                batch_proof_method_ids[0].method_id.into(),
                Some(state_diff_60kb.clone()),
                false,
                l1_hash.as_raw_hash().to_byte_array(),
                vec![commitment_3.clone(), commitment_4.clone()],
                vec![commitment_3_state_root, commitment_4_state_root],
                Some(commitment_2.serialize_and_calculate_sha_256()),
            );

        let _ = batch_prover_da_service
            .test_send_separate_chunk_transaction_with_fee_rate(
                DaTxRequest::ZKProof(verifiable_60kb_batch_proof),
                1,
            )
            .await
            .unwrap();

        // In total 2 chunks 1 aggregate with all of them having reveal and commit txs we should have 6 txs in mempool
        da.wait_mempool_len(6, Some(TEN_MINS)).await?;

        let txs = da.get_raw_mempool().await?;
        assert_eq!(txs.len(), 6);

        let mut reveals = [Txid::all_zeros(), Txid::all_zeros(), Txid::all_zeros()];

        let mut commits = Vec::with_capacity(3);

        for txid in txs {
            let tx = da
                .get_transaction(&txid, None)
                .await?
                .transaction()
                .unwrap();

            let parsed = parse_relevant_transaction(&tx);
            match parsed {
                Ok(ParsedTransaction::Aggregate(_)) => {
                    // Make sure the aggregate tx is the last one
                    reveals[2] = txid;
                }
                Ok(ParsedTransaction::Chunk(_)) => {
                    // all chunks come before the aggregate
                    if reveals[0] == Txid::all_zeros() {
                        reveals[0] = txid;
                    } else if reveals[1] == Txid::all_zeros() {
                        reveals[1] = txid;
                    }
                }
                Err(_) => commits.push(txid),
                _ => {}
            }
        }

        commits.push(reveals[0]);
        let commits_and_first_chunk = commits.clone();

        // First chunk in block n
        da.generate_block(
            addr.clone(),
            commits_and_first_chunk
                .iter()
                .map(|tx| tx.to_string())
                .collect(),
        )
        .await?;

        // Second chunk in block n+1
        da.generate_block(addr.clone(), vec![reveals[1].to_string()])
            .await?;

        // Aggregate in block n+2
        da.generate_block(addr.clone(), vec![reveals[2].to_string()])
            .await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;
        // Wait for full node to process proofs
        full_node.wait_for_l1_height(finalized_height, None).await?;
        // Wait for lcp to process proofs
        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        // Check that the proof was processed
        let last_proven_l2_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(last_proven_l2_height.height, 40);
        assert_eq!(last_proven_l2_height.commitment_index, 4);
        // Expect the same results in lcp
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;
        assert_eq!(
            lcp_output.last_l2_height,
            U64::from(last_proven_l2_height.height)
        );
        assert_eq!(
            lcp_output.last_sequencer_commitment_index,
            U32::from(last_proven_l2_height.commitment_index)
        );

        //////

        let last_state_root = lcp_output.l2_state_root;

        // Test chunk1 in previous l1 blocks and chunk2 comes after aggregate should fail because aggregate is not the last one
        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 60kb (compressed size) batch proof this batch proof will consist of 2 chunks and 1 aggregate transactions because 60kb/40kb = 2 chunks
        let verifiable_60kb_batch_proof =
            create_serialized_fake_receipt_batch_proof_with_state_roots(
                last_state_root,
                60,
                batch_proof_method_ids[0].method_id.into(),
                Some(state_diff_60kb.clone()),
                false,
                l1_hash.as_raw_hash().to_byte_array(),
                vec![commitment_5.clone(), commitment_6.clone()],
                vec![commitment_5_state_root, commitment_6_state_root],
                Some(commitment_4.serialize_and_calculate_sha_256()),
            );

        let _ = batch_prover_da_service
            .test_send_separate_chunk_transaction_with_fee_rate(
                DaTxRequest::ZKProof(verifiable_60kb_batch_proof),
                1,
            )
            .await
            .unwrap();

        // In total 2 chunks 1 aggregate with all of them having reveal and commit txs we should have 6 txs in mempool
        da.wait_mempool_len(6, Some(TEN_MINS)).await?;

        let txs = da.get_raw_mempool().await?;
        assert_eq!(txs.len(), 6);

        let mut reveals = [Txid::all_zeros(), Txid::all_zeros(), Txid::all_zeros()];

        let mut commits = Vec::with_capacity(3);

        for txid in txs {
            let tx = da
                .get_transaction(&txid, None)
                .await?
                .transaction()
                .unwrap();

            let parsed = parse_relevant_transaction(&tx);
            match parsed {
                Ok(ParsedTransaction::Aggregate(_)) => {
                    // Make sure the aggregate tx is in the middle
                    reveals[1] = txid;
                }
                Ok(ParsedTransaction::Chunk(_)) => {
                    // all chunks come before the aggregate
                    if reveals[0] == Txid::all_zeros() {
                        reveals[0] = txid;
                    } else if reveals[2] == Txid::all_zeros() {
                        reveals[2] = txid;
                    }
                }
                Err(_) => commits.push(txid),
                _ => {}
            }
        }

        commits.push(reveals[0]);
        let commits_and_first_chunk = commits.clone();

        // First chunk in block n
        da.generate_block(
            addr.clone(),
            commits_and_first_chunk
                .iter()
                .map(|tx| tx.to_string())
                .collect(),
        )
        .await?;

        // Secondly aggregate in block n+1
        da.generate_block(addr.clone(), vec![reveals[1].to_string()])
            .await?;

        // Finally last chunk in block n+2
        da.generate_block(addr.clone(), vec![reveals[2].to_string()])
            .await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;
        // Wait for full node to process proofs
        full_node.wait_for_l1_height(finalized_height, None).await?;
        // Wait for lcp to process proofs
        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        // Check that the proof was not processed and state root etc is still the same
        let last_proven_l2_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(last_proven_l2_height.height, 40);
        assert_eq!(last_proven_l2_height.commitment_index, 4);
        // Expect the same results in lcp
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;
        assert_eq!(
            lcp_output.last_l2_height,
            U64::from(last_proven_l2_height.height)
        );
        assert_eq!(
            lcp_output.last_sequencer_commitment_index,
            U32::from(last_proven_l2_height.commitment_index)
        );

        Ok(())
    }
}
#[tokio::test]
async fn test_full_node_lcp_chunk_proof() -> Result<()> {
    TestCaseRunner::new(FullNodeLcpChunkProofTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .set_citrea_cli_path(get_citrea_cli_path())
    .run()
    .await
}

struct FullNodeL1SyncHaltOnMerkleRootMismatch {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for FullNodeL1SyncHaltOnMerkleRootMismatch {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_sequencer: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 50000,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(145)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        /*
        Sequencer publish 1-5
        Creates commitment 1
        Full node sync 1-5
        Verify commitment 1
        send commitment with wrong merkle root index 2 last l2 10
        create a proof over range [2] with that wrong commitment
        Observe full node l1 sync halt at commitment 2 l1 height - 1


        */
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();
        let full_node = f.full_node.as_mut().unwrap();

        for _ in 1..=10 {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer.client.wait_for_l2_block(10, None).await?;
        full_node.wait_for_l2_height(10, None).await?; // let it sync

        let range1 = sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), U64::from(5))
            .await?;

        let merkle_root = calculate_merkle_root(&range1);

        let correct_commitment = SequencerCommitment {
            index: 1,
            l2_end_block_number: 5,
            merkle_root,
        };
        let task_executor = self.task_manager.executor();
        let sequencer_da_service = spawn_bitcoin_da_service(
            task_executor,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        sequencer_da_service
            .send_transaction_with_fee_rate(DaTxRequest::SequencerCommitment(correct_commitment), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;
        let last_committed_l2 = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(last_committed_l2.commitment_index, 1);
        assert_eq!(last_committed_l2.height, 5);

        let wrong_merkle_root_commitment = SequencerCommitment {
            index: 2,
            l2_end_block_number: 10,
            merkle_root: [0u8; 32],
        };

        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(wrong_merkle_root_commitment),
                1,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Full node should never process this commitment
        sleep(Duration::from_secs(15)).await;
        let full_node_last_scanned_l1_height = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await?;

        // Full node should halt at the last commitment, so the last processed l1 height should be the finalized height - 1
        assert_eq!(
            full_node_last_scanned_l1_height.to::<u64>(),
            finalized_height - 1
        );

        // Also confirm that l2 sync continues
        for _ in 11..=20 {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer.client.wait_for_l2_block(20, None).await?;

        // See that l2 sync still works
        full_node.wait_for_l2_height(20, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // See full node l1 sync is still halted
        let full_node_last_scanned_l1_height = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await?;
        assert_eq!(
            full_node_last_scanned_l1_height.to::<u64>(),
            finalized_height - 1
        );

        for _ in 21..=30 {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer.client.wait_for_l2_block(30, None).await?;

        // See that l2 sync still works
        full_node.wait_for_l2_height(30, None).await?;

        let seq_block = sequencer
            .client
            .http_client()
            .get_l2_block_by_number(U64::from(30))
            .await?;
        let full_node_block = full_node
            .client
            .http_client()
            .get_l2_block_by_number(U64::from(30))
            .await?;
        // See that rpc works for full node and the blocks are the same
        assert_eq!(seq_block, full_node_block);

        Ok(())
    }
}

#[tokio::test]
async fn test_full_node_l1_sync_halt_on_merkle_root_mismatch() -> Result<()> {
    TestCaseRunner::new(FullNodeL1SyncHaltOnMerkleRootMismatch {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .set_citrea_cli_path(get_citrea_cli_path())
    .run()
    .await
}

struct UnsyncedFirstCommitmentTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for UnsyncedFirstCommitmentTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_sequencer: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 5,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(145)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        /*
        Stop full node
        Sequencer publish 1-10
        Creates commitments 1-2
        Stop sequencer (so full node can't sync)

        Start full node
        Full node is unable to process commitments, assert last committed l2 is None

        Start sequencer
        Full node sync 1-10
        Generate one l1 block
        Assert last committed l2 is 10 with commitment index 2
        */
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();
        let full_node = f.full_node.as_mut().unwrap();

        // stop the full node
        full_node.wait_until_stopped().await?;

        for _ in 1..=10 {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer.client.wait_for_l2_block(10, None).await?;

        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // stop sequencer so full node doesn't sync
        sequencer.wait_until_stopped().await?;

        // restart full node
        full_node.start(None, None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;
        let last_committed_l2 = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?;
        assert!(last_committed_l2.is_none());

        sequencer.start(None, None).await?;
        full_node.wait_for_l2_height(10, None).await?; // let it sync
        da.generate(1).await?; // trigger processing pending commitments
        let finalized_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;
        let last_committed_l2 = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?;
        assert_eq!(
            last_committed_l2,
            Some(L2HeightAndIndex {
                height: 10,
                commitment_index: 2,
            })
        );
        Ok(())
    }
}

#[tokio::test]
async fn test_unsynced_first_commitment() -> Result<()> {
    TestCaseRunner::new(UnsyncedFirstCommitmentTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .set_citrea_cli_path(get_citrea_cli_path())
    .run()
    .await
}

#[allow(clippy::too_many_arguments)]
pub fn create_serialized_fake_receipt_batch_proof_with_state_roots(
    initial_state_root: [u8; 32],
    last_l2_height: u64,
    method_id: [u32; 8],
    state_diff: Option<CumulativeStateDiff>,
    malformed_journal: bool,
    last_l1_hash_on_bitcoin_light_client_contract: [u8; 32],
    sequencer_commitments: Vec<SequencerCommitment>,
    state_roots_of_seq_comms: Vec<[u8; 32]>,
    prev_sequencer_commitment_hash: Option<[u8; 32]>,
) -> Vec<u8> {
    let sequencer_commitment_hashes = sequencer_commitments
        .iter()
        .map(|c| c.serialize_and_calculate_sha_256())
        .collect::<Vec<_>>();
    let previous_commitment_index = if sequencer_commitments[0].index == 1 {
        None
    } else {
        Some(sequencer_commitments[0].index - 1)
    };
    let mut state_roots = vec![initial_state_root];

    // For the sake of easiness of impl tests, we can use merkle root as state root
    state_roots.extend(state_roots_of_seq_comms);

    let batch_proof_output = BatchProofCircuitOutput::V3(BatchProofCircuitOutputV3 {
        state_roots,
        last_l2_height,
        final_l2_block_hash: [0u8; 32],
        state_diff: state_diff.unwrap_or_default(),
        sequencer_commitment_hashes,
        last_l1_hash_on_bitcoin_light_client_contract,
        sequencer_commitment_index_range: (
            sequencer_commitments[0].index,
            sequencer_commitments[sequencer_commitments.len() - 1].index,
        ),
        previous_commitment_index,
        previous_commitment_hash: prev_sequencer_commitment_hash,
    });
    let mut output_serialized = borsh::to_vec(&batch_proof_output).unwrap();

    // Distorts the output and make it unparsable
    if malformed_journal {
        output_serialized.push(1u8);
    }

    let claim = MaybePruned::Value(ReceiptClaim::ok(method_id, output_serialized.clone()));
    let fake_receipt = FakeReceipt::new(claim);
    // Receipt with verifiable claim
    let receipt = InnerReceipt::Fake(fake_receipt);
    bincode::serialize(&receipt).unwrap()
}
