use async_trait::async_trait;
use bitcoin_da::service::FINALITY_DEPTH;
use citrea_e2e::config::TestCaseConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use citrea_fullnode::rpc::FullNodeRpcClient;
use sov_ledger_rpc::LedgerRpcClient;

use super::get_citrea_path;

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

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let citrea_cli = f.citrea_cli.as_ref().unwrap();

        let min_soft_confirmations_per_commitment = sequencer.min_l2_blocks_per_commitment();

        let initial_committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?;
        assert_eq!(initial_committed_height, None);

        let initial_proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?;
        assert_eq!(initial_proven_height, None);

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
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

        assert_eq!(
            committed_height.height,
            min_soft_confirmations_per_commitment
        );
        assert_eq!(committed_height.commitment_index, 0);

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?;

        assert!(proven_height.is_none());

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
        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();

        // Proven height should match the committed height
        assert_eq!(proven_height.height, committed_height.height);
        assert_eq!(
            proven_height.commitment_index,
            committed_height.commitment_index
        );

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let second_commitment_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(second_commitment_l1_height, None)
            .await?;

        let committed_height2 = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?
            .unwrap();

        assert_eq!(
            committed_height2.height,
            min_soft_confirmations_per_commitment * 2
        );
        assert_eq!(committed_height2.commitment_index, 1);

        // Proven height should still be at the first commitment
        let proven_height2 = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();

        assert_eq!(proven_height2.height, min_soft_confirmations_per_commitment);
        assert_eq!(proven_height2.commitment_index, 0);

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

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?;

        assert!(proven_height.is_none());

        let committed_height = full_node
            .client
            .http_client()
            .get_last_committed_l2_height()
            .await?;

        assert!(committed_height.is_none());

        Ok(())
    }
}

#[tokio::test]
async fn test_l2_status_heights() -> Result<()> {
    TestCaseRunner::new(L2StatusTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
