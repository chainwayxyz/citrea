use async_trait::async_trait;
use bitcoin_da::service::FINALITY_DEPTH;
use citrea_common::backup::BackupRpcClient;
use citrea_e2e::config::TestCaseConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;

use super::get_citrea_path;

struct BackupRestoreTest;

#[async_trait]
impl TestCase for BackupRestoreTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();

        let min_soft_confirmations = sequencer.min_soft_confirmations_per_commitment();
        let sequencer_base_dir = &sequencer.config.base.dir;

        for _ in 0..min_soft_confirmations {
            sequencer.client.send_publish_batch_request().await?;
        }
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        let backup_path = sequencer_base_dir.join("backup");
        let backup_height = sequencer
            .client
            .ledger_get_head_soft_confirmation_height()
            .await?;

        // Go through a full craete/validate/info flow
        sequencer
            .client
            .http_client()
            .backup_create(Some(backup_path.clone()))
            .await?;

        let validation = sequencer
            .client
            .http_client()
            .backup_validate(backup_path.clone())
            .await?;

        assert!(validation.is_valid);

        let backup_info = sequencer
            .client
            .http_client()
            .backup_info(backup_path.clone())
            .await?;

        assert!(backup_info.contains_key("ledger"));
        assert!(backup_info.contains_key("state"));
        assert!(backup_info.contains_key("native-db"));

        for _ in 0..min_soft_confirmations {
            sequencer.client.send_publish_batch_request().await?;
        }

        let height = sequencer
            .client
            .ledger_get_head_soft_confirmation_height()
            .await?;
        assert!(height > backup_height);

        let extra_args = vec![
            "--restore-db".to_string(),
            backup_path.display().to_string(),
        ];
        sequencer.restart(None, Some(extra_args)).await?;

        // Verify state was properly restored by checking block height
        let restored_height = sequencer
            .client
            .ledger_get_head_soft_confirmation_height()
            .await?;

        assert_eq!(restored_height, backup_height,);

        Ok(())
    }
}

#[tokio::test]
#[ignore]
async fn test_backup_restore() -> Result<()> {
    TestCaseRunner::new(BackupRestoreTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
