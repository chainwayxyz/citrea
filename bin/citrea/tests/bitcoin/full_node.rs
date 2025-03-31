use alloy_primitives::U64;
use async_trait::async_trait;
use bitcoin_da::service::FINALITY_DEPTH;
use bitcoincore_rpc::RpcApi;
use citrea_common::tasks::manager::TaskManager;
use citrea_e2e::config::{BitcoinConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use citrea_fullnode::rpc::FullNodeRpcClient;
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::da::{DaTxRequest, SequencerCommitment};
use sov_rollup_interface::rpc::block::L2BlockResponse;

use crate::bitcoin::batch_prover_test::wait_for_zkproofs;
use crate::bitcoin::utils::{spawn_bitcoin_da_service, DaServiceKeyKind};

use super::{get_citrea_cli_path, get_citrea_path};

fn calculate_merkle_root(blocks: &[Option<L2BlockResponse>]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = blocks
        .iter()
        .flatten()
        .map(|block| block.header.hash)
        .collect();

    let tree = rs_merkle::MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&leaves);
    tree.root().unwrap()
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
        Some(175)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let citrea_cli = f.citrea_cli.as_ref().unwrap();
        let full_node_http_client = full_node.client.http_client().clone();

        let min_l2_blocks_per_commitment = sequencer.min_l2_blocks_per_commitment();

        let initial_committed_height = full_node_http_client.get_last_committed_l2_height().await?;
        assert_eq!(initial_committed_height, None);

        let initial_proven_height = full_node_http_client.get_last_proven_l2_height().await?;
        assert_eq!(initial_proven_height, None);

        let initial_heights_by_l1 = full_node_http_client
            .get_l2_status_heights_by_l1_height(0)
            .await?;
        assert_eq!(initial_heights_by_l1.committed, 0);
        assert_eq!(initial_heights_by_l1.proven, 0);

        for _ in 0..min_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(commitment_l1_height, None)
            .await?;

        let committed_height = full_node_http_client
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        assert_eq!(committed_height.height, min_l2_blocks_per_commitment);
        assert_eq!(committed_height.commitment_index, 0);

        let proven_height = full_node_http_client.get_last_proven_l2_height().await?;

        assert!(proven_height.is_none());

        let status_at_commitment_l1_height = full_node_http_client
            .get_l2_status_heights_by_l1_height(commitment_l1_height)
            .await?;
        assert_eq!(
            status_at_commitment_l1_height.committed,
            min_l2_blocks_per_commitment
        );
        assert_eq!(status_at_commitment_l1_height.proven, 0);

        batch_prover
            .wait_for_l1_height(commitment_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
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
            status_at_proof_l1_height.committed,
            min_l2_blocks_per_commitment
        );
        assert_eq!(
            status_at_proof_l1_height.proven,
            min_l2_blocks_per_commitment
        );

        for _ in 0..min_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let second_commitment_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(second_commitment_l1_height, None)
            .await?;

        let committed_height2 = full_node_http_client
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        assert_eq!(committed_height2.height, min_l2_blocks_per_commitment * 2);
        assert_eq!(committed_height2.commitment_index, 1);

        // Proven height should still be at the first commitment
        let proven_height2 = full_node_http_client
            .get_last_proven_l2_height()
            .await?
            .unwrap();

        assert_eq!(proven_height2.height, min_l2_blocks_per_commitment);
        assert_eq!(proven_height2.commitment_index, 0);

        // Try a future non-existent L1 height
        let future_l1_height = second_commitment_l1_height + 1_000;
        let status = full_node
            .client
            .http_client()
            .get_l2_status_heights_by_l1_height(future_l1_height)
            .await?;
        assert_eq!(status.committed, min_l2_blocks_per_commitment * 2);
        assert_eq!(status.proven, min_l2_blocks_per_commitment);

        full_node.wait_until_stopped().await?;

        // Rollback to genesis and check that committed and proven height are correctly resetted
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
                    "0",
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
        assert_eq!(status_after_rollback.committed, 0);
        assert_eq!(status_after_rollback.proven, 0);

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

#[derive(Default)]
struct OutOfOrderCommitmentsTest {
    task_manager: TaskManager<()>,
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

    async fn cleanup(&self) -> Result<()> {
        self.task_manager.abort().await;
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let min_l2_blocks_per_commitment = sequencer.min_l2_blocks_per_commitment();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            &mut self.task_manager,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        for _ in 0..min_l2_blocks_per_commitment * 2 {
            sequencer.client.send_publish_batch_request().await?;
        }

        let first_range = sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), U64::from(min_l2_blocks_per_commitment))
            .await?;

        let first_merkle_root = calculate_merkle_root(&first_range);

        let second_range = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(min_l2_blocks_per_commitment + 1),
                U64::from(min_l2_blocks_per_commitment * 2),
            )
            .await?;

        let second_merkle_root = calculate_merkle_root(&second_range);

        let first_commitment = SequencerCommitment {
            merkle_root: first_merkle_root,
            l2_end_block_number: min_l2_blocks_per_commitment,
            index: 0,
        };

        let second_commitment = SequencerCommitment {
            merkle_root: second_merkle_root,
            l2_end_block_number: min_l2_blocks_per_commitment * 2,
            index: 1,
        };

        da.wait_mempool_len(4, None).await?;

        // Restart and remove txs from mempool
        da.restart(None, None).await?;
        let mempool = da.get_raw_mempool().await?;
        assert_eq!(mempool.len(), 0, "Mempool should be empty after restart");

        // Send the second commitment first
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(second_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
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

        da.generate(FINALITY_DEPTH).await?;
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
            min_l2_blocks_per_commitment * 2
        );
        assert_eq!(final_committed_height.commitment_index, 1);

        Ok(())
    }
}

#[tokio::test]
async fn test_out_of_order_commitments() -> Result<()> {
    TestCaseRunner::new(OutOfOrderCommitmentsTest::default())
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

#[derive(Default)]
struct ConflictingCommitmentsTest {
    task_manager: TaskManager<()>,
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

    async fn cleanup(&self) -> Result<()> {
        self.task_manager.abort().await;
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let min_l2_blocks_per_commitment = sequencer.min_l2_blocks_per_commitment();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            &mut self.task_manager,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        for _ in 0..min_l2_blocks_per_commitment {
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

        let first_range = sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), U64::from(min_l2_blocks_per_commitment))
            .await?;

        let correct_merkle_root = calculate_merkle_root(&first_range);
        let commitment_a = SequencerCommitment {
            merkle_root: correct_merkle_root,
            l2_end_block_number: min_l2_blocks_per_commitment,
            index: 0,
        };

        // Create another conflicting commitment B with same index but different l2_end_block_number
        let commitment_b = SequencerCommitment {
            merkle_root: correct_merkle_root,
            l2_end_block_number: min_l2_blocks_per_commitment - 1,
            index: 0,
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
        da.generate(FINALITY_DEPTH).await?;
        let l1_height_a = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(l1_height_a, None).await?;

        // Assert that commitment A was processed
        let committed_height_a = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        assert_eq!(committed_height_a.height, min_l2_blocks_per_commitment);
        assert_eq!(committed_height_a.commitment_index, 0);

        // Send conflicting commitment B
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment_b.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(FINALITY_DEPTH).await?;
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
        assert_eq!(committed_height_b.height, min_l2_blocks_per_commitment);
        assert_eq!(committed_height_b.commitment_index, 0);

        for _ in 0..min_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        let second_range = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(min_l2_blocks_per_commitment + 1),
                U64::from(min_l2_blocks_per_commitment * 2),
            )
            .await?;

        let second_merkle_root = calculate_merkle_root(&second_range);
        let commitment_c = SequencerCommitment {
            merkle_root: second_merkle_root,
            l2_end_block_number: min_l2_blocks_per_commitment * 2,
            index: 1,
        };

        // Send commitment C that follows A
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitment_c.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(FINALITY_DEPTH).await?;
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
            min_l2_blocks_per_commitment * 2
        );
        assert_eq!(final_committed_height.commitment_index, 1);

        Ok(())
    }
}

#[tokio::test]
async fn test_conflicting_commitments() -> Result<()> {
    TestCaseRunner::new(ConflictingCommitmentsTest::default())
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

#[derive(Default)]
struct OutOfRangeProofTest {
    task_manager: TaskManager<()>,
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

    async fn cleanup(&self) -> Result<()> {
        self.task_manager.abort().await;
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let citrea_cli = f.citrea_cli.as_ref().unwrap();

        let min_l2_blocks_per_commitment = sequencer.min_l2_blocks_per_commitment();

        println!("f.initial_da_height : {:?}", f.initial_da_height);

        let bitcoin_da_service = spawn_bitcoin_da_service(
            &mut self.task_manager,
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        // Generate two commitments to test pending proof over commitment ranges
        for _ in 0..min_l2_blocks_per_commitment * 2 {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(4, None).await?;
        println!("got seqcoms");
        da.generate(FINALITY_DEPTH).await?;
        let commitments_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(commitments_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        println!("got batch proofs");
        da.generate(FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;

        println!("Waiting for height {proof_l1_height} fullnode");
        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        let first_range = sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), U64::from(min_l2_blocks_per_commitment))
            .await?;
        let first_merkle_root = calculate_merkle_root(&first_range);
        let commitment0 = SequencerCommitment {
            merkle_root: first_merkle_root,
            l2_end_block_number: min_l2_blocks_per_commitment,
            index: 0,
        };

        let second_range = sequencer
            .client
            .http_client()
            .get_l2_block_range(
                U64::from(min_l2_blocks_per_commitment + 1),
                U64::from(min_l2_blocks_per_commitment * 2),
            )
            .await?;
        let second_merkle_root = calculate_merkle_root(&second_range);
        let commitment1 = SequencerCommitment {
            merkle_root: second_merkle_root,
            l2_end_block_number: min_l2_blocks_per_commitment * 2,
            index: 1,
        };

        let proof = wait_for_zkproofs(full_node, proof_l1_height, None, 1)
            .await
            .unwrap()[0]
            .clone()
            .proof;

        // Rollback bitcoin to initial height and drop existing txs so that we can re-send them out of order
        let initial_height_hash = da.get_block_hash(f.initial_da_height + 1).await?;
        da.invalidate_block(&initial_height_hash).await?;
        let block_count = da.get_block_count().await?;
        assert_eq!(block_count, f.initial_da_height);

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
                    "0",
                    "--sequencer-commitment-index",
                    "0",
                ],
            )
            .await?;

        full_node.start(None, None).await?;

        // Send the proof first and should be kept as pending
        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(proof), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(proof_l1_height, None).await?;

        // The proof should be stored as pending and not be processed
        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?;
        assert!(
            proven_height.is_none(),
            "No proof should be processed yet without commitments"
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::SequencerCommitment(commitment0), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(FINALITY_DEPTH).await?;
        let commitment0_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(commitment0_l1_height, None)
            .await?;

        // The first commitment should be processed but the proof should still be pending
        // since it depends on both commitments
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(committed_height.height, min_l2_blocks_per_commitment);
        assert_eq!(committed_height.commitment_index, 0);

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?;
        assert!(
            proven_height.is_none(),
            "Proof should still be pending without the second commitment"
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::SequencerCommitment(commitment1), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(FINALITY_DEPTH).await?;
        let commitment1_l1_height = da.get_finalized_height(None).await?;
        full_node
            .wait_for_l1_height(commitment1_l1_height, None)
            .await?;

        // Both commitments should be processed and the pending proof should now be processed too
        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();
        assert_eq!(committed_height.height, min_l2_blocks_per_commitment * 2);
        assert_eq!(committed_height.commitment_index, 1);

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(proven_height.height, min_l2_blocks_per_commitment * 2);
        assert_eq!(proven_height.commitment_index, 1);

        Ok(())
    }
}

#[tokio::test]
async fn test_out_of_range_proof() -> Result<()> {
    TestCaseRunner::new(OutOfRangeProofTest::default())
        .set_citrea_path(get_citrea_path())
        .set_citrea_cli_path(get_citrea_cli_path())
        .run()
        .await
}
