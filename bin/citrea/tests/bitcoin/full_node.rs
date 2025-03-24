use std::sync::Arc;

use alloy_primitives::U64;
use async_trait::async_trait;
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig, FINALITY_DEPTH};
use bitcoin_da::spec::RollupParams;
use bitcoincore_rpc::RpcApi;
use citrea_common::tasks::manager::{TaskManager, TaskType};
use citrea_e2e::config::{BitcoinConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::NodeKind;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use citrea_fullnode::rpc::FullNodeRpcClient;
use citrea_primitives::REVEAL_TX_PREFIX;
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::da::{DaTxRequest, SequencerCommitment};
use sov_rollup_interface::rpc::block::L2BlockResponse;

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
        Some(150)
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

        let da_config = &da.config;
        let bitcoin_da_service_config = BitcoinServiceConfig {
            node_url: format!(
                "http://127.0.0.1:{}/wallet/{}",
                da_config.rpc_port,
                NodeKind::Bitcoin
            ),
            node_username: da_config.rpc_user.clone(),
            node_password: da_config.rpc_password.clone(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                // Sequencer da private key
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(),
            ),
            tx_backup_dir: Self::test_config()
                .dir
                .join("tx_backup_dir")
                .display()
                .to_string(),
            monitoring: Default::default(),
            mempool_space_url: None,
        };
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let bitcoin_da_service = Arc::new(
            BitcoinService::new_with_wallet_check(
                bitcoin_da_service_config,
                RollupParams {
                    reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
                },
                tx,
            )
            .await
            .unwrap(),
        );

        self.task_manager.spawn(TaskType::Secondary, |tk| {
            bitcoin_da_service.clone().run_da_queue(rx, tk)
        });

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

        let da_config = &da.config;
        let bitcoin_da_service_config = BitcoinServiceConfig {
            node_url: format!(
                "http://127.0.0.1:{}/wallet/{}",
                da_config.rpc_port,
                NodeKind::Bitcoin
            ),
            node_username: da_config.rpc_user.clone(),
            node_password: da_config.rpc_password.clone(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(),
            ),
            tx_backup_dir: Self::test_config()
                .dir
                .join("tx_backup_dir")
                .display()
                .to_string(),
            monitoring: Default::default(),
            mempool_space_url: None,
        };
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let bitcoin_da_service = Arc::new(
            BitcoinService::new_with_wallet_check(
                bitcoin_da_service_config,
                RollupParams {
                    reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
                },
                tx,
            )
            .await
            .unwrap(),
        );

        self.task_manager.spawn(TaskType::Secondary, |tk| {
            bitcoin_da_service.clone().run_da_queue(rx, tk)
        });

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
