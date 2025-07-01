use std::collections::HashMap;
use std::path::{Path, PathBuf};

use alloy_primitives::U64;
use async_trait::async_trait;
use citrea_common::backup::{
    BackupInfoResponse, BackupRpcClient, BackupValidationResponse, CreateBackupInfo,
};
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{LightClientProverConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::Sequencer;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use sov_ledger_rpc::LedgerRpcClient;

use super::{get_citrea_cli_path, get_citrea_path};
use crate::bitcoin::utils::{wait_for_prover_job, wait_for_prover_job_count, wait_for_zkproofs};

const API_KEY: &str = "12345";

// Helper method to call `backup_create` with API_KEY
async fn create_backup(
    client: &HttpClient,
    path: Option<&Path>,
) -> anyhow::Result<CreateBackupInfo> {
    Ok(client
        .request(
            "backup_create",
            rpc_params![path, Some(API_KEY.to_string())],
        )
        .await?)
}

// Helper method to call `backup_validate` with API_KEY
async fn validate_backup(
    client: &HttpClient,
    path: Option<&Path>,
) -> anyhow::Result<BackupValidationResponse> {
    Ok(client
        .request(
            "backup_validate",
            rpc_params!(path, Some(API_KEY.to_string())),
        )
        .await?)
}

// Helper method to call `backup_info` with API_KEY
async fn get_backup_info(
    client: &HttpClient,
    path: Option<&Path>,
) -> anyhow::Result<HashMap<String, Vec<BackupInfoResponse>>> {
    Ok(client
        .request("backup_info", rpc_params!(path, Some(API_KEY.to_string())))
        .await?)
}

/**
 * Tests backup and post-rollback backup for the sequencer node.
 *
 * # Flow
 * 1. Tests RPC guards, auth and non-existent paths
 * 2. Generate L2 blocks to alter state before backing up
 * 3. Create initial backup and verify backup information
 * 4. Call `backup_validate` and assert backup integrity
 * 5. Create incremental backups
 * 6. Generate more blocks and create new backups to verify backup block height tracking
 * 7. Test restore flow:
 *    - Generate additional blocks
 *    - Restore from backup and verify correct block height
 * 8. Test backup/restore after rollback:
 *    - Generate additional blocks
 *    - Rollback to earlier state
 *    - Create post-rollback backup
 *    - Generate more blocks
 *    - Restore from post-rollback backup and verify state
 */
struct BackupSequencerTest;

impl BackupSequencerTest {
    async fn test_guards(sequencer: &mut Sequencer) -> Result<()> {
        let client = sequencer.client.http_client();

        // Should fail as backup methods are protected and api_key is not passed as hidden second param
        let backup = sequencer.client.http_client().backup_create(None).await;

        assert!(backup.is_err());

        // Should fail as path is invalid
        let invalid_path = PathBuf::from("/tmp/invalid");
        let invalid_validation = validate_backup(client, Some(&invalid_path)).await?;

        assert!(!invalid_validation.is_valid);
        assert_eq!(invalid_validation.backup_path, invalid_path);
        assert!(invalid_validation.message.is_some());

        Ok(())
    }
}

#[async_trait]
impl TestCase for BackupSequencerTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_citrea_cli: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_mut().unwrap();
        let citrea_cli = f.citrea_cli.as_mut().unwrap();

        let client = sequencer.client.http_client().clone();

        Self::test_guards(sequencer).await?;

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        let start_height = sequencer.client.ledger_get_head_l2_block_height().await?;

        let backup_path = sequencer.config.base.dir.join("backup");
        let backup_info = create_backup(&client, Some(&backup_path)).await?;

        assert_eq!(backup_info.node_kind, "sequencer");
        assert_eq!(backup_info.backup_id, 1);
        assert!(backup_info.created_at > 0);
        assert_eq!(backup_info.backup_path, backup_path);
        assert_eq!(backup_info.l2_block_height.unwrap(), start_height);

        let validation = validate_backup(&client, Some(&backup_path)).await?;
        assert!(validation.is_valid);
        assert_eq!(validation.backup_path, backup_path);
        assert!(validation.message.is_none());

        let backup_info = get_backup_info(&client, Some(&backup_path)).await?;

        // Verify all required databases are present in the backup
        assert!(backup_info.contains_key("ledger"));
        assert!(backup_info.contains_key("state"));
        assert!(backup_info.contains_key("native"));

        // Check that each database has valid backup info
        for (_, infos) in backup_info.iter() {
            // There should be at least one backup
            assert!(!infos.is_empty());

            for info in infos {
                assert_eq!(info.backup_id, 1);
                assert!(info.timestamp > 0);
                assert!(info.size > 0);
                assert!(info.num_files > 0);
            }
        }

        // Create incremental backup
        let incremental_backup = create_backup(&client, Some(&backup_path)).await?;
        assert_eq!(incremental_backup.backup_id, 2);

        // Generate more blocks and assert backup height increases alongside
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        let current_height = sequencer.client.ledger_get_head_l2_block_height().await?;

        // Update incremental backup after height increase
        let incremental_backup = create_backup(&client, Some(&backup_path)).await?;

        assert_eq!(incremental_backup.backup_id, 3);
        assert_eq!(incremental_backup.l2_block_height.unwrap(), current_height);

        // Create new non-incremental backup
        let backup_path_2 = sequencer.config.base.dir.join("backup_2");
        let backup_info_2 = create_backup(&client, Some(&backup_path_2)).await?;

        assert_eq!(backup_info_2.l2_block_height.unwrap(), current_height);

        // Test restore flow

        // Generate blocks before restoring so that highest block doesn't match backup height
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        let current_height = sequencer.client.ledger_get_head_l2_block_height().await?;

        sequencer.wait_until_stopped().await?;

        citrea_cli
            .run(
                "restore-backup",
                &[
                    "--node-kind",
                    "sequencer",
                    "--db-path",
                    sequencer.config.rollup.storage.path.to_str().unwrap(),
                    "--backup-path",
                    backup_path.to_str().unwrap(),
                    "--backup-id",
                    &incremental_backup.backup_id.to_string(),
                ],
            )
            .await?;

        sequencer.start(None, None).await?;

        // Assert that heights is properly restored to the expected height
        let restored_l2_height = sequencer.client.ledger_get_head_l2_block_height().await?;
        assert_eq!(
            restored_l2_height,
            incremental_backup.l2_block_height.unwrap()
        );
        assert_ne!(restored_l2_height, current_height);

        // Test backup and restore post rollback
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        let current_height = sequencer.client.ledger_get_head_l2_block_height().await?;

        // Create a new backup after adding blocks
        let backup_path_3 = sequencer.config.base.dir.join("backup_3");
        let backup_3 = create_backup(&client, Some(&backup_path_3)).await?;

        let backup_3_height = backup_3.l2_block_height.unwrap();
        assert_eq!(backup_3_height, current_height);

        // Rollback to start l2 height
        let rollback_target_l2 = start_height;
        let rollback_target_l1 = f.initial_da_height;
        let last_seq_commitment_index = 0;

        sequencer.wait_until_stopped().await?;

        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "sequencer",
                    "--db-path",
                    sequencer.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    &rollback_target_l2.to_string(),
                    "--l1-target",
                    &rollback_target_l1.to_string(),
                    "--sequencer-commitment-index",
                    &last_seq_commitment_index.to_string(),
                ],
            )
            .await?;

        sequencer.start(None, None).await?;

        // Assert that node is now at rolled back start_height
        let rolled_back_height = sequencer.client.ledger_get_head_l2_block_height().await?;
        assert_eq!(rolled_back_height, start_height);

        let post_rollback_backup_path = sequencer.config.base.dir.join("post_rollback_backup");
        let post_rollback_backup = create_backup(&client, Some(&post_rollback_backup_path)).await?;

        let post_rollback_backup_height = post_rollback_backup.l2_block_height.unwrap();
        assert_eq!(post_rollback_backup_height, rolled_back_height);

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer.wait_until_stopped().await?;

        citrea_cli
            .run(
                "restore-backup",
                &[
                    "--node-kind",
                    "sequencer",
                    "--db-path",
                    sequencer.config.rollup.storage.path.to_str().unwrap(),
                    "--backup-path",
                    post_rollback_backup_path.to_str().unwrap(),
                    "--backup-id",
                    &post_rollback_backup.backup_id.to_string(),
                ],
            )
            .await?;

        sequencer.start(None, None).await?;

        let restored_height = sequencer.client.ledger_get_head_l2_block_height().await?;
        assert_eq!(restored_height, post_rollback_backup_height);
        assert_eq!(restored_height, rolled_back_height);

        Ok(())
    }
}

#[tokio::test]
async fn test_backup_sequencer() -> Result<()> {
    TestCaseRunner::new(BackupSequencerTest)
        .set_citrea_path(get_citrea_path())
        .set_citrea_cli_path(get_citrea_cli_path())
        .run()
        .await
}

/**
 * Tests backup and post-rollback backup for the full node.
 *
 * # Flow
 * 1. Generate L2 blocks and commitments on the sequencer
 * 2. Wait for full node to sync L1 and L2 blocks
 * 3. Create initial backup capturing current state
 * 4. Validate backup integrity and verify backup info
 * 5. Generate additional blocks and commitments
 * 6. Restore from backup:
 *    - Stop all nodes to prevent synchronization during restore
 *    - Restore full node to backed up state
 *    - Verify L1 and L2 heights match expected backup state
 *    - Compare restored block with sequencer's block to ensure consistency
 * 7. Test rollback:
 *    - Generate more blocks
 *    - Rollback to specific L1 and L2 target heights
 *    - Create post-rollback backup
 *    - Generate more blocks
 *    - Restore from post-rollback backup
 *    - Verify L1 and L2 heights match expected rollback state
 */
struct BackupFullNodeTest;

#[async_trait]
impl TestCase for BackupFullNodeTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_full_node: true,
            with_citrea_cli: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let citrea_cli = f.citrea_cli.as_mut().unwrap();

        let client = full_node.client.http_client().clone();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;

        let start_l2_height = full_node.client.ledger_get_head_l2_block_height().await?;
        let start_l1_height: u64 = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await?
            .to();

        let backup_path = full_node.config.base.dir.join("backup");
        let create_backup_info = create_backup(&client, Some(&backup_path)).await?;

        assert_eq!(create_backup_info.node_kind, "full-node");
        assert_eq!(create_backup_info.backup_id, 1);
        assert!(create_backup_info.created_at > 0);
        assert_eq!(create_backup_info.backup_path, backup_path);
        assert_eq!(create_backup_info.l2_block_height.unwrap(), start_l2_height);
        assert_eq!(create_backup_info.l1_block_height.unwrap(), start_l1_height);

        let validation = validate_backup(&client, Some(&backup_path)).await?;
        assert!(validation.is_valid);
        assert_eq!(validation.backup_path, backup_path);
        assert!(validation.message.is_none());

        let backup_info = get_backup_info(&client, Some(&backup_path)).await?;

        assert!(backup_info.contains_key("ledger"));
        assert!(backup_info.contains_key("state"));
        assert!(backup_info.contains_key("native"));

        for (key, infos) in backup_info.iter() {
            assert!(!infos.is_empty(), "No backups found for db: {key}");

            for info in infos {
                assert_eq!(info.backup_id, 1);
                assert!(info.timestamp > 0);
                assert!(info.size > 0);
                assert!(info.num_files > 0);
            }
        }

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;

        full_node.wait_until_stopped().await?;
        // Stop sequencer so that fullnode doesn't sync on restart
        sequencer.wait_until_stopped().await?;

        citrea_cli
            .run(
                "restore-backup",
                &[
                    "--node-kind",
                    "full-node",
                    "--db-path",
                    full_node.config.rollup.storage.path.to_str().unwrap(),
                    "--backup-path",
                    backup_path.to_str().unwrap(),
                    "--backup-id",
                    &create_backup_info.backup_id.to_string(),
                ],
            )
            .await?;

        full_node.start(None, None).await?;

        let restored_l2_height = full_node.client.ledger_get_head_l2_block_height().await?;
        let restored_l1_height: u64 = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await?
            .to();

        assert_eq!(restored_l2_height, start_l2_height);
        assert_eq!(restored_l1_height, start_l1_height);

        // Restart sequencer to generate blocks
        sequencer.start(None, None).await?;

        // Test restored state against sequencer
        let restored_block = full_node
            .client
            .http_client()
            .get_l2_block_by_number(U64::from(restored_l2_height))
            .await?
            .unwrap();

        let sequencer_block = sequencer
            .client
            .http_client()
            .get_l2_block_by_number(U64::from(restored_l2_height))
            .await?
            .unwrap();

        assert_eq!(restored_block, sequencer_block);

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;

        let rollback_target_l2 = start_l2_height;
        let rollback_target_l1 = start_l1_height;
        let last_seq_commitment_index = 0;

        full_node.wait_until_stopped().await?;
        // Stop sequencer so that fullnode doesn't sync on restart
        sequencer.wait_until_stopped().await?;
        // Stop da so that fullnode doesn't sync on restart
        da.wait_until_stopped().await?;

        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "full-node",
                    "--db-path",
                    full_node.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    &rollback_target_l2.to_string(),
                    "--l1-target",
                    &rollback_target_l1.to_string(),
                    "--sequencer-commitment-index",
                    &last_seq_commitment_index.to_string(),
                ],
            )
            .await?;

        full_node.start(None, None).await?;

        // Assert that node is now at rolled back heights
        let rolled_back_l2_height = full_node.client.ledger_get_head_l2_block_height().await?;
        let rolled_back_l1_height: u64 = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await?
            .to();

        assert_eq!(rolled_back_l2_height, rollback_target_l2);
        assert_eq!(rolled_back_l1_height, rollback_target_l1);

        // Test backup after rollback
        let post_rollback_backup_path = full_node.config.base.dir.join("post_rollback_backup");
        let post_rollback_backup = create_backup(&client, Some(&post_rollback_backup_path)).await?;

        // Restart da
        da.start(None, None).await?;
        // Restart sequencer
        sequencer.start(None, None).await?;

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;

        // Restore from post-rollback backup
        full_node.wait_until_stopped().await?;
        // Stop sequencer so that fullnode doesn't sync on restart
        sequencer.wait_until_stopped().await?;
        // Stop da so that fullnode doesn't sync on restart
        da.wait_until_stopped().await?;

        citrea_cli
            .run(
                "restore-backup",
                &[
                    "--node-kind",
                    "full-node",
                    "--db-path",
                    full_node.config.rollup.storage.path.to_str().unwrap(),
                    "--backup-path",
                    post_rollback_backup_path.to_str().unwrap(),
                    "--backup-id",
                    &post_rollback_backup.backup_id.to_string(),
                ],
            )
            .await?;

        full_node.start(None, None).await?;

        // Assert the heights match the post-rollback state
        let final_l2_height = full_node.client.ledger_get_head_l2_block_height().await?;
        let final_l1_height: u64 = full_node
            .client
            .http_client()
            .get_last_scanned_l1_height()
            .await?
            .to();

        assert_eq!(final_l2_height, rolled_back_l2_height);
        assert_eq!(final_l1_height, rolled_back_l1_height);

        Ok(())
    }
}

#[tokio::test]
async fn test_backup_full_node() -> Result<()> {
    TestCaseRunner::new(BackupFullNodeTest)
        .set_citrea_path(get_citrea_path())
        .set_citrea_cli_path(get_citrea_cli_path())
        .run()
        .await
}

/**
 * Tests backup and post-rollback backup for the batch prover.
 *
 * # Flow
 * 1. Generate L2 blocks and commitments
 * 2. Wait for batch prover to process commitment and generate proof
 * 3. Verify proof with full node
 * 4. Create batch prover backup
 * 5. Generate second set of blocks/commitments and process second proof
 * 6. Test restore from backup:
 *    - Restore batch prover to state after first proof
 *    - Verify it reprocesses the second commitment
 *    - Verify that it resends proofs to DA but that it's correctly skipped by fullnode
 *    - Compare restored proof output with original second proof
 * 7. Test rollback:
 *    - Rollback to state after first commitment/proof
 *    - Create post-rollback backup
 *    - Generate third set of blocks/commitments
 *    - Process third proof
 *    - Restore from post-rollback backup
 *    - Verify batch prover correctly reprocesses third commitment
 *    - Confirm proof output matches original third proof
 */
struct BackupBatchProverTest;

#[async_trait]
impl TestCase for BackupBatchProverTest {
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
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();
        let batch_prover = f.batch_prover.as_mut().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let citrea_cli = f.citrea_cli.as_mut().unwrap();

        let client = batch_prover.client.http_client().clone();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(commitment_l1_height, None)
            .await?;

        let job_ids = wait_for_prover_job_count(batch_prover, 1, None).await?;
        assert_eq!(job_ids.len(), 1);
        let job_id = job_ids[0];

        let response = wait_for_prover_job(batch_prover, job_id, None).await?;
        let first_proof = response.proof.unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_l1_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(proof_l1_height, None).await?;
        let proofs = wait_for_zkproofs(full_node, proof_l1_height, None, 1).await?;
        assert_eq!(proofs.len(), 1);

        let backup_path = batch_prover.config.base.dir.join("backup");
        let backup_info = create_backup(&client, Some(&backup_path)).await?;

        assert_eq!(backup_info.node_kind, "batch-prover");
        assert_eq!(backup_info.backup_id, 1);
        assert!(backup_info.created_at > 0);
        assert_eq!(backup_info.backup_path, backup_path);
        assert!(backup_info.l2_block_height.is_some());

        let validation = validate_backup(&client, Some(&backup_path)).await?;
        assert!(validation.is_valid);
        assert_eq!(validation.backup_path, backup_path);
        assert!(validation.message.is_none());

        let backup_info_map = get_backup_info(&client, Some(&backup_path)).await?;
        assert!(backup_info_map.contains_key("ledger"));
        assert!(backup_info_map.contains_key("state"));
        assert!(backup_info_map.contains_key("native"));

        for (key, infos) in backup_info_map.iter() {
            assert!(!infos.is_empty(), "No backups found for db: {key}");

            for info in infos {
                assert_eq!(info.backup_id, 1);
                assert!(info.timestamp > 0);
                assert!(info.size > 0);
                assert!(info.num_files > 0);
            }
        }

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let second_commitment_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(second_commitment_l1_height, None)
            .await?;

        let job_ids = wait_for_prover_job_count(batch_prover, 2, None).await?;
        assert_eq!(job_ids.len(), 2);
        let second_job_id = job_ids[0];
        let second_response = wait_for_prover_job(batch_prover, second_job_id, None).await?;
        let second_proof = second_response.proof.unwrap();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let second_proof_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(second_proof_l1_height, None)
            .await?;
        let all_proofs = wait_for_zkproofs(full_node, second_proof_l1_height, None, 1).await?;
        assert_eq!(all_proofs.len(), 1);

        batch_prover.wait_until_stopped().await?;

        citrea_cli
            .run(
                "restore-backup",
                &[
                    "--node-kind",
                    "batch-prover",
                    "--db-path",
                    batch_prover.config.rollup.storage.path.to_str().unwrap(),
                    "--backup-path",
                    backup_path.to_str().unwrap(),
                    "--backup-id",
                    &backup_info.backup_id.to_string(),
                ],
            )
            .await?;

        batch_prover.start(None, None).await?;

        batch_prover
            .wait_for_l1_height(second_commitment_l1_height, None)
            .await?;

        let restored_job_ids = wait_for_prover_job_count(batch_prover, 1, None).await?;
        assert_eq!(restored_job_ids.len(), 1);
        let restored_job_id = restored_job_ids[0];

        let restored_response = wait_for_prover_job(batch_prover, restored_job_id, None).await?;
        let restored_proof = restored_response.proof.unwrap();

        assert_eq!(
            restored_proof.proof_output.final_state_root(),
            second_proof.proof_output.final_state_root()
        );
        assert_eq!(
            restored_proof.proof_output.last_l2_height,
            second_proof.proof_output.last_l2_height
        );

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let restored_proof_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(restored_proof_l1_height, None)
            .await?;
        let proofs = full_node
            .client
            .http_client()
            .get_verified_batch_proofs_by_slot_height(U64::from(restored_proof_l1_height))
            .await?;
        // Proof should have been skipped as duplicate by fullnode
        assert!(proofs.is_none());

        batch_prover.wait_until_stopped().await?;

        // Target the L1 height after the first commitment but before the second
        let rollback_target_l1 = commitment_l1_height;
        let proof_output = first_proof.proof_output;

        let rollback_target_commitment_index = 0;
        let rollback_target_l2 = proof_output.last_l2_height.to::<u64>();

        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "batch-prover",
                    "--db-path",
                    batch_prover.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    &rollback_target_l2.to_string(),
                    "--l1-target",
                    &rollback_target_l1.to_string(),
                    "--sequencer-commitment-index",
                    &rollback_target_commitment_index.to_string(),
                ],
            )
            .await?;

        batch_prover.start(None, None).await?;

        // After rollback, batch prover should re-process the second commitment
        batch_prover
            .wait_for_l1_height(second_commitment_l1_height, None)
            .await?;

        let rollback_job_ids = wait_for_prover_job_count(batch_prover, 1, None).await?;
        assert_eq!(rollback_job_ids.len(), 1);
        let rollback_job_id = rollback_job_ids[0];
        let rollback_response = wait_for_prover_job(batch_prover, rollback_job_id, None).await?;
        let rollback_proof = rollback_response.proof.unwrap();

        assert_eq!(
            rollback_proof.proof_output.final_state_root(),
            second_proof.proof_output.final_state_root()
        );
        assert_eq!(
            rollback_proof.proof_output.last_l2_height,
            second_proof.proof_output.last_l2_height
        );

        // Create a post-rollback backup
        let post_rollback_backup_path = batch_prover.config.base.dir.join("post_rollback_backup");
        let post_rollback_backup = create_backup(&client, Some(&post_rollback_backup_path)).await?;

        // Generate more blocks for a third commitment
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let third_commitment_l1_height = da.get_finalized_height(None).await?;

        // Wait for batch prover to process the third commitment
        batch_prover
            .wait_for_l1_height(third_commitment_l1_height, None)
            .await?;

        let third_job_ids = wait_for_prover_job_count(batch_prover, 2, None).await?;
        assert_eq!(third_job_ids.len(), 2);
        let third_job_id = third_job_ids[0];

        let third_response = wait_for_prover_job(batch_prover, third_job_id, None).await?;
        let third_proof = third_response.proof.unwrap();

        batch_prover.wait_until_stopped().await?;

        citrea_cli
            .run(
                "restore-backup",
                &[
                    "--node-kind",
                    "batch-prover",
                    "--db-path",
                    batch_prover.config.rollup.storage.path.to_str().unwrap(),
                    "--backup-path",
                    post_rollback_backup_path.to_str().unwrap(),
                    "--backup-id",
                    &post_rollback_backup.backup_id.to_string(),
                ],
            )
            .await?;

        batch_prover.start(None, None).await?;

        batch_prover
            .wait_for_l1_height(third_commitment_l1_height, None)
            .await?;

        let final_job_ids = wait_for_prover_job_count(batch_prover, 1, None).await?;
        assert_eq!(final_job_ids.len(), 1);
        let final_job_id = final_job_ids[0];

        let final_response = wait_for_prover_job(batch_prover, final_job_id, None).await?;
        let final_proof = final_response.proof.unwrap();

        assert_eq!(
            final_proof.proof_output.final_state_root(),
            third_proof.proof_output.final_state_root()
        );
        assert_eq!(
            final_proof.proof_output.last_l2_height,
            third_proof.proof_output.last_l2_height
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_backup_batch_prover() -> Result<()> {
    TestCaseRunner::new(BackupBatchProverTest)
        .set_citrea_path(get_citrea_path())
        .set_citrea_cli_path(get_citrea_cli_path())
        .run()
        .await
}

/**
 * Tests backup and post-rollback backup for the light client prover.
 *
 * # Flow
 * 1. Generate blocks, commitments, and proofs with sequencer and batch prover
 * 2. Wait for light client prover to process batch proofs
 * 3. Create backup of light client prover state
 * 4. Generate second set of blocks, commitments and proofs
 * 5. Test restore from backup:
 *    - Restore light client prover to backed up state
 *    - Verify it processes second proof correctly
 *    - Compare restored light client proof with original
 * 6. Test rollback:
 *    - Rollback to first batch proof L1 height
 *    - Create post-rollback backup
 *    - Generate third set of blocks, commitments and proofs
 *    - Process third light client proof
 *    - Restore from post-rollback backup
 *    - Verify light client correctly processes all proofs
 *    - Compare final light client proof state with original
 */
struct BackupLightClientProverTest;

#[async_trait]
impl TestCase for BackupLightClientProverTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            with_citrea_cli: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(195)
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            initial_da_height: 201,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();
        let batch_prover = f.batch_prover.as_mut().unwrap();
        let light_client_prover = f.light_client_prover.as_mut().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let citrea_cli = f.citrea_cli.as_mut().unwrap();

        let client = light_client_prover.client.http_client().clone();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(commitment_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, None)
            .await?;

        let first_proof = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;

        assert!(first_proof.is_some());

        full_node
            .wait_for_l1_height(batch_proof_l1_height, None)
            .await?;

        let batch_proofs = wait_for_zkproofs(full_node, batch_proof_l1_height, None, 1).await?;
        assert_eq!(batch_proofs.len(), 1);

        let backup_path = light_client_prover.config.base.dir.join("backup");
        let backup_info = create_backup(&client, Some(&backup_path)).await?;

        assert_eq!(backup_info.node_kind, "light-client-prover");
        assert_eq!(backup_info.backup_id, 1);
        assert!(backup_info.created_at > 0);
        assert_eq!(backup_info.backup_path, backup_path);
        assert!(backup_info.l2_block_height.is_none());

        let validation = validate_backup(&client, Some(&backup_path)).await?;
        assert!(validation.is_valid);
        assert_eq!(validation.backup_path, backup_path);
        assert!(validation.message.is_none());

        let backup_info_map = get_backup_info(&client, Some(&backup_path)).await?;

        assert!(backup_info_map.contains_key("ledger"));
        assert!(backup_info_map.contains_key("state"));
        assert!(backup_info_map.contains_key("native"));

        for (key, infos) in backup_info_map.iter() {
            assert!(!infos.is_empty(), "No backups found for db: {key}");

            for info in infos {
                assert_eq!(info.backup_id, 1);
                assert!(info.timestamp > 0);
                assert!(info.size > 0);
                assert!(info.num_files > 0);
            }
        }

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let second_commitment_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(second_commitment_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let second_proof_l1_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(second_proof_l1_height, None)
            .await?;

        let second_proof = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(second_proof_l1_height)
            .await?
            .unwrap();

        full_node
            .wait_for_l1_height(second_proof_l1_height, None)
            .await?;

        let batch_proofs = wait_for_zkproofs(full_node, second_proof_l1_height, None, 1).await?;
        assert_eq!(batch_proofs.len(), 1);

        light_client_prover.wait_until_stopped().await?;

        citrea_cli
            .run(
                "restore-backup",
                &[
                    "--node-kind",
                    "light-client-prover",
                    "--db-path",
                    light_client_prover
                        .config
                        .rollup
                        .storage
                        .path
                        .to_str()
                        .unwrap(),
                    "--backup-path",
                    backup_path.to_str().unwrap(),
                    "--backup-id",
                    &backup_info.backup_id.to_string(),
                ],
            )
            .await?;

        light_client_prover.start(None, None).await?;

        light_client_prover
            .wait_for_l1_height(second_proof_l1_height, None)
            .await?;

        let restored_proof = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(second_proof_l1_height)
            .await?
            .unwrap();

        assert_eq!(
            restored_proof.light_client_proof_output.l2_state_root,
            second_proof.light_client_proof_output.l2_state_root
        );
        assert_eq!(
            restored_proof.light_client_proof_output.last_l2_height,
            second_proof.light_client_proof_output.last_l2_height
        );

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let restored_proof_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(restored_proof_l1_height, None)
            .await?;

        light_client_prover.wait_until_stopped().await?;

        let rollback_target_l1 = light_client_prover.config.node.initial_da_height;

        // Doesn't matter for LCP
        let rollback_target_commitment_index = 0;
        let rollback_target_l2 = 0;

        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "light-client",
                    "--db-path",
                    light_client_prover
                        .config
                        .rollup
                        .storage
                        .path
                        .to_str()
                        .unwrap(),
                    "--l2-target",
                    &rollback_target_l2.to_string(),
                    "--l1-target",
                    &rollback_target_l1.to_string(),
                    "--sequencer-commitment-index",
                    &rollback_target_commitment_index.to_string(),
                ],
            )
            .await?;

        light_client_prover.start(None, None).await?;

        light_client_prover
            .wait_for_l1_height(second_proof_l1_height, None)
            .await?;

        let rollback_proof = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(second_proof_l1_height)
            .await?
            .unwrap();

        assert_eq!(
            rollback_proof.light_client_proof_output.l2_state_root,
            second_proof.light_client_proof_output.l2_state_root
        );
        assert_eq!(
            rollback_proof.light_client_proof_output.last_l2_height,
            second_proof.light_client_proof_output.last_l2_height
        );

        let post_rollback_backup_path = light_client_prover
            .config
            .base
            .dir
            .join("post_rollback_backup");
        let post_rollback_backup = create_backup(&client, Some(&post_rollback_backup_path)).await?;

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let third_commitment_l1_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(third_commitment_l1_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let third_proof_l1_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(third_proof_l1_height, None)
            .await?;

        let third_proof = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(third_proof_l1_height)
            .await?
            .unwrap();

        light_client_prover.wait_until_stopped().await?;

        citrea_cli
            .run(
                "restore-backup",
                &[
                    "--node-kind",
                    "light-client-prover",
                    "--db-path",
                    light_client_prover
                        .config
                        .rollup
                        .storage
                        .path
                        .to_str()
                        .unwrap(),
                    "--backup-path",
                    post_rollback_backup_path.to_str().unwrap(),
                    "--backup-id",
                    &post_rollback_backup.backup_id.to_string(),
                ],
            )
            .await?;

        light_client_prover.start(None, None).await?;

        light_client_prover
            .wait_for_l1_height(third_proof_l1_height, None)
            .await?;

        let final_proof = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(third_proof_l1_height)
            .await?
            .unwrap();

        assert_eq!(
            final_proof.light_client_proof_output.l2_state_root,
            third_proof.light_client_proof_output.l2_state_root
        );
        assert_eq!(
            final_proof.light_client_proof_output.last_l2_height,
            third_proof.light_client_proof_output.last_l2_height
        );

        assert!(light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(third_proof_l1_height)
            .await?
            .is_some());

        Ok(())
    }
}

#[tokio::test]
async fn test_backup_light_client_prover() -> Result<()> {
    TestCaseRunner::new(BackupLightClientProverTest)
        .set_citrea_path(get_citrea_path())
        .set_citrea_cli_path(get_citrea_cli_path())
        .run()
        .await
}
