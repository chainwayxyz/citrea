use std::time::Duration;

use alloy_primitives::{U32, U64};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin_da::error::BitcoinServiceError;
use bitcoin_da::service::{BitcoinService, UtxoSelectionMode};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::{BitcoinNode, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::config::{BitcoinConfig, LightClientProverConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use reth_tasks::TaskManager;
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::da::{DaTxRequest, SequencerCommitment};
use sov_rollup_interface::rpc::BatchProofMethodIdRpcResponse;
use sov_rollup_interface::services::da::DaService;

use super::light_client_test::create_random_state_diff;
use super::{get_citrea_cli_path, get_citrea_path};
use crate::bitcoin::full_node::create_serialized_fake_receipt_batch_proof_with_state_roots;
use crate::bitcoin::utils::{
    spawn_bitcoin_da_prover_service, spawn_bitcoin_da_prover_service_with_utxo_selection_mode,
};

struct DaTransactionQueueingTest {
    task_manager: TaskManager,
}

impl DaTransactionQueueingTest {
    // Test for `MempoolRejection("package-mempool-limits, possibly exceeds descendant size limit for tx 6a0c9e3c2fed9cbac73c88031e7333d0ce2242a664e3141ba028b765b0b1e562 [limit: 101000]` error
    // Send 4 100kb proofs. The 4th one will be tipping the total package size over the 101kvb limit and be rejected with package-too-large error
    #[allow(clippy::too_many_arguments)]
    async fn test_package_mempool_limits(
        &self,
        da: &BitcoinNode,
        da_service: &BitcoinService,
        finalized_height: u64,
        genesis_state_root: [u8; 32],
        batch_proof_method_ids: &[BatchProofMethodIdRpcResponse],
        commitment_1: &SequencerCommitment,
        commitment_1_state_root: [u8; 32],
    ) -> Result<()> {
        let state_diff_100kb = create_random_state_diff(100);
        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 100kb batch proof
        let verifiable_100kb_batch_proof =
            create_serialized_fake_receipt_batch_proof_with_state_roots(
                genesis_state_root,
                20,
                batch_proof_method_ids[0].method_id.into(),
                Some(state_diff_100kb.clone()),
                false,
                l1_hash.as_raw_hash().to_byte_array(),
                vec![commitment_1.clone()],
                vec![commitment_1_state_root],
                None,
            );

        // Fill mempool
        for i in 1..=3 {
            da_service
                .send_transaction_with_fee_rate(
                    DaTxRequest::ZKProof(verifiable_100kb_batch_proof.clone()),
                    1,
                )
                .await?;
            da.wait_mempool_len(8 * i, None).await?;
        }

        da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::ZKProof(verifiable_100kb_batch_proof.clone()),
                1,
            )
            .await?;

        // Last tx chunk should hit mempool policy `DEFAULT_DESCENDANT_SIZE_LIMIT_KVB` limit
        // The three first proofs should hit the mempool + 1 chunk
        da.wait_mempool_len(8 * 3 + 2, None).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 26);

        // Assert that all queued txs are monitored
        let monitored_txs = da_service.monitoring.get_monitored_txs().await;
        assert_eq!(monitored_txs.len(), 32);

        // Try to send when queue is already filled up.
        // This is to test that utxos is correctly selected and that it's doesn't hang on waiting for list of queued txids to be returned
        let res = da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::ZKProof(verifiable_100kb_batch_proof.clone()),
                1,
            )
            .await;

        assert!(matches!(res, Err(BitcoinServiceError::QueueNotEmpty)));

        // Send transaction hangs until a new block is detected
        // Tests that transactions properly waits for block notification
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                da.generate(1).await?;
            }
            _ = da_service.send_transaction(DaTxRequest::ZKProof(verifiable_100kb_batch_proof.clone())) => {
            }
        }

        // We mine the first three proofs + the 1 chunk pair and make sure that the remaining chunks and aggregate
        // and the extra proof is properly queued and sent on next block when mempool size is freed
        // Assert that all chunks were mined and mempool space is freed
        assert_eq!(da.get_raw_mempool().await?.len(), 0);

        let height = da.get_block_count().await?;
        let hash = da.get_block_hash(height).await?;
        let block = da_service.get_block_by_hash(hash.into()).await?;
        let (relevant_txs, _, _) = da_service.extract_relevant_blobs_with_proof(&block);

        assert_eq!(relevant_txs.len(), 13);

        // Remaining chunks and aggregate + extra queued proof should now hit the mempool
        da.wait_mempool_len(8 + 6, None).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 8 + 6);
        da.generate(1).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 0);

        let height = da.get_block_count().await?;
        let hash = da.get_block_hash(height).await?;
        let block = da_service.get_block_by_hash(hash.into()).await?;
        let (relevant_txs, _, _) = da_service.extract_relevant_blobs_with_proof(&block);
        assert_eq!(relevant_txs.len(), 7);

        da.generate(1).await?;

        Ok(())
    }

    // Test for `MempoolRejection("package-too-large")` error
    // Single 400kb state diff
    #[allow(clippy::too_many_arguments)]
    async fn test_package_too_large(
        &self,
        da: &BitcoinNode,
        da_service: &BitcoinService,
        finalized_height: u64,
        genesis_state_root: [u8; 32],
        batch_proof_method_ids: &[BatchProofMethodIdRpcResponse],
        commitment_1: &SequencerCommitment,
        commitment_1_state_root: [u8; 32],
    ) -> Result<()> {
        let state_diff_400kb = create_random_state_diff(400);

        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 400kb batch proof
        let verifiable_400kb_batch_proof =
            create_serialized_fake_receipt_batch_proof_with_state_roots(
                genesis_state_root,
                20,
                batch_proof_method_ids[0].method_id.into(),
                Some(state_diff_400kb.clone()),
                false,
                l1_hash.as_raw_hash().to_byte_array(),
                vec![commitment_1.clone()],
                vec![commitment_1_state_root],
                None,
            );

        // This over the mempool limit proof should be accepted and split up over multiple blocks
        let res = da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::ZKProof(verifiable_400kb_batch_proof.clone()),
                1,
            )
            .await;
        assert!(res.is_ok());

        // Qeuue is already not empty and proof cannot be sent.
        let res = da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_400kb_batch_proof), 1)
            .await;
        assert!(res.is_err());

        da.wait_mempool_len(18, None).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 18);

        // Assert that all queued txs are monitored
        let monitored_txs = da_service.monitoring.get_monitored_txs().await;
        assert_eq!(monitored_txs.len(), 64);

        da.generate(1).await?;
        // Assert that all chunks were mined and mempool space is freed
        assert_eq!(da.get_raw_mempool().await?.len(), 0);

        let height = da.get_block_count().await?;
        let hash = da.get_block_hash(height).await?;
        let block = da_service.get_block_by_hash(hash.into()).await?;
        let (relevant_txs, _, _) = da_service.extract_relevant_blobs_with_proof(&block);
        assert_eq!(relevant_txs.len(), 9);

        // Keep track of hash in which chunks start to be mined
        let rollback_first_hash = hash;

        da.wait_mempool_len(6, None).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 6);
        da.generate(1).await?;
        // Assert that all chunks and aggregate were mined
        assert_eq!(da.get_raw_mempool().await?.len(), 0);

        let height = da.get_block_count().await?;
        let hash = da.get_block_hash(height).await?;
        let block = da_service.get_block_by_hash(hash.into()).await?;
        let (relevant_txs, _, _) = da_service.extract_relevant_blobs_with_proof(&block);
        assert_eq!(relevant_txs.len(), 3);

        // Test re-org behaviour when over mempool policy limit

        // Invalidate last block and make sure txs are back in mempool
        da.invalidate_block(&hash).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 6);

        // Track that 5 last txs that will be dropped on next block invalidation
        let dropped_txs = &da.get_raw_mempool().await?[1..]; // first commit will still be part of the mempool

        da.invalidate_block(&rollback_first_hash).await?;
        // Should be 6 + 18 if all mined txs were restored to mempool but 5 txs are dropped due to being over mempool policy limit
        assert_eq!(da.get_raw_mempool().await?.len(), 18 + 1);
        let remaining_txs = da.get_raw_mempool().await?;
        assert!(dropped_txs.iter().all(|tx| !remaining_txs.contains(tx)));

        da.generate(1).await?;

        // Make sure txs are rebroadcasted from monitoring service
        da.wait_mempool_len(5, None).await?;
        let raw_mempool = da.get_raw_mempool().await?;
        assert_eq!(dropped_txs, raw_mempool);

        Ok(())
    }
}

#[async_trait]
impl TestCase for DaTransactionQueueingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_sequencer: true,
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec![
                "-persistmempool=0",
                "-walletbroadcast=0",
                "-limitancestorcount=100", // Prevent test from hitting default ancestor count limit of 25
                "-limitdescendantcount=100", // Prevent test from hitting default descendant count limit of 25
                "-fallbackfee=0.00001",
            ],
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
        let sequencer = f.sequencer.as_mut().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let light_client_prover = f.light_client_prover.as_mut().unwrap();

        let da_service =
            spawn_bitcoin_da_prover_service(&task_executor, &da.config, Self::test_config().dir)
                .await;
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to create light client proof.
        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
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

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer_client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for full node to process sequencer commitments
        full_node
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;
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

        self.test_package_mempool_limits(
            da,
            &da_service,
            finalized_height,
            genesis_state_root,
            &batch_proof_method_ids,
            &commitment_1,
            commitment_1_state_root,
        )
        .await?;

        self.test_package_too_large(
            da,
            &da_service,
            finalized_height,
            genesis_state_root,
            &batch_proof_method_ids,
            &commitment_1,
            commitment_1_state_root,
        )
        .await?;
        Ok(())
    }
}

#[tokio::test]
async fn test_queue_da_transactions() -> Result<()> {
    TestCaseRunner::new(DaTransactionQueueingTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .set_citrea_cli_path(get_citrea_cli_path())
    .run()
    .await
}

struct DaTransactionQueueingUtxoSelectionModeOldestTest {
    task_manager: TaskManager,
}

impl DaTransactionQueueingUtxoSelectionModeOldestTest {
    // Test for `MempoolRejection("package-mempool-limits, possibly exceeds descendant size limit for tx 6a0c9e3c2fed9cbac73c88031e7333d0ce2242a664e3141ba028b765b0b1e562 [limit: 101000]` error
    // Send 4 100kb proofs. The 4th one will be tipping the total package size over the 101kvb limit and be rejected with package-too-large error
    #[allow(clippy::too_many_arguments)]
    async fn test_package_mempool_limits(
        &self,
        da: &BitcoinNode,
        da_service: &BitcoinService,
        finalized_height: u64,
        genesis_state_root: [u8; 32],
        batch_proof_method_ids: &[BatchProofMethodIdRpcResponse],
        commitment_1: &SequencerCommitment,
        commitment_1_state_root: [u8; 32],
    ) -> Result<()> {
        let state_diff_100kb = create_random_state_diff(100);
        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 100kb batch proof
        let verifiable_100kb_batch_proof =
            create_serialized_fake_receipt_batch_proof_with_state_roots(
                genesis_state_root,
                20,
                batch_proof_method_ids[0].method_id.into(),
                Some(state_diff_100kb.clone()),
                false,
                l1_hash.as_raw_hash().to_byte_array(),
                vec![commitment_1.clone()],
                vec![commitment_1_state_root],
                None,
            );

        // Fill mempool
        for i in 1..=3 {
            da_service
                .send_transaction_with_fee_rate(
                    DaTxRequest::ZKProof(verifiable_100kb_batch_proof.clone()),
                    1,
                )
                .await?;
            da.wait_mempool_len(8 * i, None).await?;
        }

        da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::ZKProof(verifiable_100kb_batch_proof.clone()),
                1,
            )
            .await?;

        // Last tx chunk should hit mempool policy `DEFAULT_DESCENDANT_SIZE_LIMIT_KVB` limit
        // The three first proofs should hit the mempool + 1 chunk
        da.wait_mempool_len(8 * 3 + 2, None).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 26);

        // Assert that all queued txs are monitored
        let monitored_txs = da_service.monitoring.get_monitored_txs().await;
        assert_eq!(monitored_txs.len(), 32);

        // Try to send when queue is already filled up.
        // This is to test that utxos is correctly selected and that it's doesn't hang on waiting for list of queued txids to be returned
        let res = da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::ZKProof(verifiable_100kb_batch_proof.clone()),
                1,
            )
            .await;

        assert!(res.is_ok());

        let monitored_txs = da_service.monitoring.get_monitored_txs().await;
        assert_eq!(monitored_txs.len(), 40);

        // Txs starting from a new chain should be accepted to mempool
        da.wait_mempool_len(8 * 3 + 2 + 8, None).await?;

        // We mine the first three proofs + the 1 chunk pair + the extra proof starting another UTXO chain
        // and make sure that the remaining chunks and aggregate and sent on next block when mempool size is freed
        // Assert that all chunks were mined and mempool space is freed
        assert_eq!(da.get_raw_mempool().await?.len(), 34);
        da.generate(1).await?;

        let height = da.get_block_count().await?;
        let hash = da.get_block_hash(height).await?;
        let block = da_service.get_block_by_hash(hash.into()).await?;
        let (relevant_txs, _, _) = da_service.extract_relevant_blobs_with_proof(&block);

        assert_eq!(relevant_txs.len(), 17);

        // Remaining chunks and aggregate
        da.wait_mempool_len(6, None).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 6);
        da.generate(1).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 0);

        let height = da.get_block_count().await?;
        let hash = da.get_block_hash(height).await?;
        let block = da_service.get_block_by_hash(hash.into()).await?;
        let (relevant_txs, _, _) = da_service.extract_relevant_blobs_with_proof(&block);
        assert_eq!(relevant_txs.len(), 3);

        da.generate(1).await?;

        Ok(())
    }

    // Test for `MempoolRejection("package-too-large")` error
    // Single 400kb state diff
    #[allow(clippy::too_many_arguments)]
    async fn test_package_too_large(
        &self,
        da: &BitcoinNode,
        da_service: &BitcoinService,
        finalized_height: u64,
        genesis_state_root: [u8; 32],
        batch_proof_method_ids: &[BatchProofMethodIdRpcResponse],
        commitment_1: &SequencerCommitment,
        commitment_1_state_root: [u8; 32],
    ) -> Result<()> {
        let state_diff_400kb = create_random_state_diff(400);

        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 400kb batch proof
        let verifiable_400kb_batch_proof =
            create_serialized_fake_receipt_batch_proof_with_state_roots(
                genesis_state_root,
                20,
                batch_proof_method_ids[0].method_id.into(),
                Some(state_diff_400kb.clone()),
                false,
                l1_hash.as_raw_hash().to_byte_array(),
                vec![commitment_1.clone()],
                vec![commitment_1_state_root],
                None,
            );

        // This over the mempool limit proof should be accepted and split up over multiple blocks
        let res = da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::ZKProof(verifiable_400kb_batch_proof.clone()),
                1,
            )
            .await;
        assert!(res.is_ok());

        // Should be able to send another proof that is also split up over multiple blocks
        let res = da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_400kb_batch_proof), 1)
            .await;
        assert!(res.is_ok());

        da.wait_mempool_len(18 * 2, None).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 18 * 2);

        // Assert that all queued txs are monitored
        let monitored_txs = da_service.monitoring.get_monitored_txs().await;
        assert_eq!(monitored_txs.len(), 88);

        da.generate(1).await?;
        // Assert that all chunks were mined and mempool space is freed
        assert_eq!(da.get_raw_mempool().await?.len(), 0);

        let height = da.get_block_count().await?;
        let hash = da.get_block_hash(height).await?;
        let block = da_service.get_block_by_hash(hash.into()).await?;
        let (relevant_txs, _, _) = da_service.extract_relevant_blobs_with_proof(&block);
        assert_eq!(relevant_txs.len(), 9 * 2);

        // Keep track of hash in which chunks start to be mined
        let rollback_first_hash = hash;

        da.wait_mempool_len(6 * 2, None).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 6 * 2);
        da.generate(1).await?;
        // Assert that all chunks and aggregate were mined
        assert_eq!(da.get_raw_mempool().await?.len(), 0);

        let height = da.get_block_count().await?;
        let hash = da.get_block_hash(height).await?;
        let block = da_service.get_block_by_hash(hash.into()).await?;
        let (relevant_txs, _, _) = da_service.extract_relevant_blobs_with_proof(&block);
        assert_eq!(relevant_txs.len(), 3 * 2);

        // Test re-org behaviour when over mempool policy limit
        // Assert that the two utxo chains are independent

        // Invalidate last block and make sure txs are back in mempool
        da.invalidate_block(&hash).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 6 * 2);

        // Track that 5 last txs of each utxo chain will be dropped on next block invalidation
        let dropped_txs = &da.get_raw_mempool().await?[2..];

        da.invalidate_block(&rollback_first_hash).await?;
        // Should be (6 + 18) * 2 if all mined txs were restored to mempool but 5 * 2 txs are dropped due to being over mempool policy limit
        assert_eq!(da.get_raw_mempool().await?.len(), (18 + 1) * 2);
        let remaining_txs = da.get_raw_mempool().await?;

        assert!(dropped_txs.iter().all(|tx| !remaining_txs.contains(tx)));

        da.generate(1).await?;

        // Make sure txs are rebroadcasted from monitoring service
        da.wait_mempool_len(5 * 2, None).await?;
        let raw_mempool = da.get_raw_mempool().await?;
        assert_eq!(dropped_txs, raw_mempool);

        Ok(())
    }
}

#[async_trait]
impl TestCase for DaTransactionQueueingUtxoSelectionModeOldestTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_sequencer: true,
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec![
                "-persistmempool=0",
                "-walletbroadcast=0",
                "-limitancestorcount=100", // Prevent test from hitting default ancestor count limit of 25
                "-limitdescendantcount=100", // Prevent test from hitting default descendant count limit of 25
                "-fallbackfee=0.00001",
            ],
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
        let sequencer = f.sequencer.as_mut().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let light_client_prover = f.light_client_prover.as_mut().unwrap();

        let da_service = spawn_bitcoin_da_prover_service_with_utxo_selection_mode(
            &task_executor,
            &da.config,
            Self::test_config().dir,
            UtxoSelectionMode::Oldest,
        )
        .await;
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to create light client proof.
        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
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

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer_client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for full node to process sequencer commitments
        full_node
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;
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

        self.test_package_mempool_limits(
            da,
            &da_service,
            finalized_height,
            genesis_state_root,
            &batch_proof_method_ids,
            &commitment_1,
            commitment_1_state_root,
        )
        .await?;

        self.test_package_too_large(
            da,
            &da_service,
            finalized_height,
            genesis_state_root,
            &batch_proof_method_ids,
            &commitment_1,
            commitment_1_state_root,
        )
        .await?;
        Ok(())
    }
}

#[tokio::test]
async fn test_queue_da_transactions_oldest_mode() -> Result<()> {
    TestCaseRunner::new(DaTransactionQueueingUtxoSelectionModeOldestTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .set_citrea_cli_path(get_citrea_cli_path())
    .run()
    .await
}
