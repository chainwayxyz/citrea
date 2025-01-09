use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::U64;
use async_trait::async_trait;
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig, FINALITY_DEPTH};
use bitcoin_da::spec::{BitcoinSpec, RollupParams};
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_batch_prover::GroupCommitments;
use citrea_common::tasks::manager::TaskManager;
use citrea_e2e::config::{
    BatchProverConfig, CitreaMode, LightClientProverConfig, SequencerConfig,
    SequencerMempoolConfig, TestCaseConfig,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::NodeKind;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use risc0_zkvm::{FakeReceipt, InnerReceipt, MaybePruned, Receipt, ReceiptClaim};
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::da::{BatchProofMethodId, DaTxRequest};
use sov_rollup_interface::zk::BatchProofCircuitOutput;

use super::batch_prover_test::wait_for_zkproofs;
use super::get_citrea_path;

const TEN_MINS: Duration = Duration::from_secs(10 * 60);
const TWENTY_MINS: Duration = Duration::from_secs(20 * 60);

struct LightClientProvingTest;

#[async_trait]
impl TestCase for LightClientProvingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            mode: CitreaMode::DevAllForks,
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
            initial_da_height: 171,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        // publish min_soft_confirmations_per_commitment confirmations
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the commitment tx
        da.generate(FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height().await?;

        // Wait for batch prover to generate proof for commitment
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that commitment is queryable
        let commitments = batch_prover
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(U64::from(commitment_l1_height))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), 1);

        // Ensure that batch proof is submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the batch proof tx
        da.generate(FINALITY_DEPTH).await?;

        let batch_proof_l1_height = da.get_finalized_height().await?;

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;
        assert!(lcp.is_some());

        let finalized_height = da.get_finalized_height().await?;
        // Wait for full node to see zkproofs
        let batch_proof =
            wait_for_zkproofs(full_node, finalized_height, Some(Duration::from_secs(7200)))
                .await
                .unwrap();

        let light_client_proof = lcp.unwrap();
        assert_eq!(
            light_client_proof
                .light_client_proof_output
                .state_root
                .to_vec(),
            batch_proof[0].proof_output.final_state_root
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_proving() -> Result<()> {
    TestCaseRunner::new(LightClientProvingTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct LightClientProvingTestMultipleProofs;

#[async_trait]
impl TestCase for LightClientProvingTestMultipleProofs {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            mode: CitreaMode::DevAllForks,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 50,
            da_update_interval_ms: 500,
            mempool_conf: SequencerMempoolConfig {
                pending_tx_size: 2000,
                max_account_slots: 2600,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            enable_recovery: false,
            proof_sampling_number: 99999999,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 171,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        let n_commitments = 2;

        // publish min_soft_confirmations_per_commitment confirmations
        for _ in 0..n_commitments * min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(n_commitments * min_soft_confirmations_per_commitment, None)
            .await?;

        // Wait for commitment txs to be submitted to DA
        da.wait_mempool_len((n_commitments * 2) as usize, Some(TEN_MINS))
            .await?;

        // Finalize the DA block which contains the commitment txs
        da.generate(FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height().await?;

        // Wait for batch prover to generate proofs for commitments
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(Duration::from_secs(1200)))
            .await
            .unwrap();

        // There are two commitments, for each commitment generate a proof
        batch_prover
            .client
            .http_client()
            .prove(commitment_l1_height, Some(GroupCommitments::OneByOne))
            .await
            .unwrap();

        // Ensure that batch proofs are submitted to DA (2x reveal & 2x commit txs)
        da.wait_mempool_len(4, Some(TWENTY_MINS)).await?;

        // Assert that commitments are queryable this also means that the batch proofs are submitted to DA
        let commitments = batch_prover
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(U64::from(commitment_l1_height))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), n_commitments as usize);

        // Finalize the DA block which contains the batch proof tx
        da.generate(FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height().await?;
        // Wait for the full node to see all process verify and store all batch proofs
        full_node
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;
        let batch_proofs = wait_for_zkproofs(full_node, batch_proof_l1_height, None).await?;
        assert_eq!(batch_proofs.len(), 2);

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await
            .unwrap();
        assert!(lcp.is_some());

        let light_client_proof = lcp.unwrap();
        assert_eq!(
            light_client_proof
                .light_client_proof_output
                .state_root
                .to_vec(),
            batch_proofs[(n_commitments - 1) as usize]
                .proof_output
                .final_state_root
        );

        assert!(light_client_proof
            .light_client_proof_output
            .unchained_batch_proofs_info
            .is_empty());

        // Generate another da block so we generate another lcp
        da.generate(1).await?;

        let last_finalized_height = da.get_finalized_height().await?;

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(last_finalized_height, Some(TEN_MINS))
            .await?;

        // Expect light client prover to have generated light client proof
        let lcp2 = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(last_finalized_height)
            .await
            .unwrap();
        assert!(lcp2.is_some());

        // Since there are no batch proofs the state root should be the same as the last one
        let light_client_proof2 = lcp2.unwrap();
        assert_eq!(
            light_client_proof2.light_client_proof_output.state_root,
            light_client_proof.light_client_proof_output.state_root
        );

        // The last processed l2 height should also be the same because there are no new batch proofs
        assert_eq!(
            light_client_proof2.light_client_proof_output.last_l2_height,
            light_client_proof.light_client_proof_output.last_l2_height
        );

        assert!(light_client_proof2
            .light_client_proof_output
            .unchained_batch_proofs_info
            .is_empty());

        // Let's generate a new batch proof
        // publish min_soft_confirmations_per_commitment confirmations
        let l2_height = sequencer
            .client
            .ledger_get_head_soft_confirmation_height()
            .await?;
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer
            .wait_for_l2_height(l2_height + min_soft_confirmations_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the commitment txs
        da.generate(FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height().await?;

        // Wait for batch prover to generate proofs for commitments
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await?;

        // There is one commitment, generate a single proof
        batch_prover
            .client
            .http_client()
            .prove(commitment_l1_height, Some(GroupCommitments::OneByOne))
            .await
            .unwrap();

        // Ensure that batch proofs is submitted to DA (1x reveal & 1x commit txs)
        da.wait_mempool_len(2, Some(TWENTY_MINS)).await?;

        // Assert that commitments are queryable this also means the batch proofs are submitted to DA with the prove rpc
        let commitments = batch_prover
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(U64::from(commitment_l1_height))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), 1);

        // Finalize the DA block which contains the batch proof tx
        da.generate(FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height().await?;
        // Wait for the full node to see all process verify and store all batch proofs
        full_node
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;
        let batch_proofs = wait_for_zkproofs(full_node, batch_proof_l1_height, None).await?;
        assert_eq!(batch_proofs.len(), 1);

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;

        // Expect light client prover to have generated light client proof
        let lcp3 = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await
            .unwrap();
        assert!(lcp3.is_some());

        let light_client_proof3 = lcp3.unwrap();
        assert_eq!(
            light_client_proof3
                .light_client_proof_output
                .state_root
                .to_vec(),
            batch_proofs[0].proof_output.final_state_root
        );

        assert_ne!(
            light_client_proof3.light_client_proof_output.last_l2_height,
            light_client_proof.light_client_proof_output.last_l2_height
        );

        assert_ne!(
            light_client_proof3.light_client_proof_output.state_root,
            light_client_proof.light_client_proof_output.state_root
        );

        assert!(light_client_proof3
            .light_client_proof_output
            .unchained_batch_proofs_info
            .is_empty());

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_proving_multiple_proofs() -> Result<()> {
    TestCaseRunner::new(LightClientProvingTestMultipleProofs)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

#[derive(Default)]
struct LightClientBatchProofMethodIdUpdateTest {
    task_manager: TaskManager<()>,
}

#[async_trait]
impl TestCase for LightClientBatchProofMethodIdUpdateTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            mode: CitreaMode::DevAllForks,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 2,
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
            initial_da_height: 171,
            ..Default::default()
        }
    }

    async fn cleanup(&self) -> Result<()> {
        self.task_manager.abort().await;
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

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
                // This is a random private key matching guest's METHOD_ID_UPGRADE_AUTHORITY
                "79122E48DF1A002FB6584B2E94D0D50F95037416C82DAF280F21CD67D17D9077".to_string(),
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
                    to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
                    to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
                },
                tx,
            )
            .await
            .unwrap(),
        );

        self.task_manager
            .spawn(|tk| bitcoin_da_service.clone().run_da_queue(rx, tk));

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        // publish min_soft_confirmations_per_commitment confirmations
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the commitment tx
        da.generate(FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height().await?;

        // Wait for batch prover to generate proof for commitment
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that commitment is queryable
        let commitments = batch_prover
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(U64::from(commitment_l1_height))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), 1);

        // Ensure that batch proof is submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the batch proof tx
        da.generate(FINALITY_DEPTH).await?;

        let batch_proof_l1_height = da.get_finalized_height().await?;

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;
        // Verify the current batch proof method ids
        assert_eq!(
            lcp_output.batch_proof_method_ids,
            vec![
                (
                    0,
                    [
                        1129196088, 155917133, 2638897170, 1970178024, 1745057535, 2098237452,
                        402126456, 572125060
                    ]
                ),
                (100, citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID)
            ],
        );

        // Send BatchProofMethodId transaction to da
        let new_batch_proof_method_id = [1u32; 8];
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::BatchProofMethodId(BatchProofMethodId {
                    method_id: new_batch_proof_method_id,
                    activation_l2_height: 200,
                }),
                1,
            )
            .await
            .unwrap();

        // Ensure that method id tx is submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the method id tx
        da.generate(FINALITY_DEPTH).await?;

        let method_id_l1_height = da.get_finalized_height().await?;

        // Wait for light client prover to process method id update
        light_client_prover
            .wait_for_l1_height(method_id_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that 1 l1 block before method id tx, still has the same batch proof method ids
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(method_id_l1_height - 1)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;
        // Verify the current batch proof method ids
        assert_eq!(
            lcp_output.batch_proof_method_ids,
            vec![
                (
                    0,
                    [
                        1129196088, 155917133, 2638897170, 1970178024, 1745057535, 2098237452,
                        402126456, 572125060
                    ],
                ),
                (100, citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
            ]
        );

        // Assert that method ids are updated
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(method_id_l1_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;
        // Verify the current batch proof method ids
        assert_eq!(
            lcp_output.batch_proof_method_ids,
            vec![
                (
                    0,
                    [
                        1129196088, 155917133, 2638897170, 1970178024, 1745057535, 2098237452,
                        402126456, 572125060
                    ],
                ),
                (100, citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
                (200, new_batch_proof_method_id)
            ]
        );

        // Generate one more empty l1 block
        da.generate(1).await?;

        // Wait for light client to process it
        light_client_prover
            .wait_for_l1_height(method_id_l1_height + 1, None)
            .await
            .unwrap();

        // Verify that previously updated method ids are being used
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(method_id_l1_height + 1)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;
        assert_eq!(
            lcp_output.batch_proof_method_ids,
            vec![
                (
                    0,
                    [
                        1129196088, 155917133, 2638897170, 1970178024, 1745057535, 2098237452,
                        402126456, 572125060
                    ],
                ),
                (100, citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
                (200, new_batch_proof_method_id)
            ]
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_batch_proof_method_id_update() -> Result<()> {
    TestCaseRunner::new(LightClientBatchProofMethodIdUpdateTest::default())
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

#[derive(Default)]
struct LightClientUnverifiableBatchProofTest {
    task_manager: TaskManager<()>,
}

#[async_trait]
impl TestCase for LightClientUnverifiableBatchProofTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 171,
            ..Default::default()
        }
    }

    async fn cleanup(&self) -> Result<()> {
        self.task_manager.abort().await;
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

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
                // This is the regtest private key of batch prover
                "56D08C2DDE7F412F80EC99A0A328F76688C904BD4D1435281EFC9270EC8C8707".to_string(),
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
                    to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
                    to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
                },
                tx,
            )
            .await
            .unwrap(),
        );

        self.task_manager
            .spawn(|tk| bitcoin_da_service.clone().run_da_queue(rx, tk));

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height().await?;

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
        let method_ids = lcp_output.batch_proof_method_ids;
        let genesis_state_root = lcp_output.state_root;

        let fork1_height = method_ids[1].0;

        let verifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            genesis_state_root,
            [1u8; 32],
            fork1_height + 1,
            method_ids[1].1,
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_batch_proof), 1)
            .await
            .unwrap();

        let verifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [2u8; 32],
            [3u8; 32],
            fork1_height * 3,
            method_ids[1].1,
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_batch_proof), 1)
            .await
            .unwrap();

        // Expect unparsable journal to be skipped
        let unparsable_batch_proof =
            create_serialized_fake_receipt_batch_proof_with_malformed_journal(
                [3u8; 32],
                [5u8; 32],
                fork1_height * 4,
                method_ids[1].1,
            );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(unparsable_batch_proof), 1)
            .await
            .unwrap();

        let verifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            [2u8; 32],
            fork1_height * 2,
            method_ids[1].1,
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_batch_proof), 1)
            .await
            .unwrap();

        // Give it a random method id to make it unverifiable
        let random_method_id = [1u32; 8];
        let unverifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [3u8; 32],
            [4u8; 32],
            fork1_height * 4,
            random_method_id,
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(unverifiable_batch_proof), 1)
            .await
            .unwrap();

        // Ensure that all four batch proofs is submitted to DA
        da.wait_mempool_len(10, None).await?;

        // Finalize the DA block which contains the batch proof txs
        da.generate(FINALITY_DEPTH).await?;

        let batch_proof_l1_height = da.get_finalized_height().await?;

        // Wait for light client prover to process unverifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof without panic but it should not have updated the state root
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The unverifiable batch proof and malformed journal batch proof should not have updated the state root or the last l2 height
        assert_eq!(lcp_output.state_root, [3u8; 32]);
        assert_eq!(lcp_output.last_l2_height, fork1_height * 3);
        assert!(lcp_output.unchained_batch_proofs_info.is_empty());

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_unverifiable_batch_proof() -> Result<()> {
    TestCaseRunner::new(LightClientUnverifiableBatchProofTest::default())
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

fn create_serialized_fake_receipt_batch_proof(
    initial_state_root: [u8; 32],
    final_state_root: [u8; 32],
    last_l2_height: u64,
    method_id: [u32; 8],
) -> Vec<u8> {
    let batch_proof_output = BatchProofCircuitOutput::<BitcoinSpec, [u8; 32]> {
        initial_state_root,
        final_state_root,
        last_l2_height,
        da_slot_hash: [0u8; 32].into(),
        prev_soft_confirmation_hash: [0u8; 32],
        final_soft_confirmation_hash: [0u8; 32],
        state_diff: BTreeMap::new(),
        sequencer_commitments_range: (0, 0),
        sequencer_da_public_key: [0u8; 32].to_vec(),
        sequencer_public_key: [0u8; 32].to_vec(),
        preproven_commitments: vec![],
    };
    let output_serialized = borsh::to_vec(&batch_proof_output).unwrap();

    let claim = MaybePruned::Value(ReceiptClaim::ok(method_id, output_serialized.clone()));
    let fake_receipt = FakeReceipt::new(claim);
    // Receipt with verifiable claim
    let receipt = Receipt::new(InnerReceipt::Fake(fake_receipt), output_serialized.clone());
    bincode::serialize(&receipt).unwrap()
}

fn create_serialized_fake_receipt_batch_proof_with_malformed_journal(
    initial_state_root: [u8; 32],
    final_state_root: [u8; 32],
    last_l2_height: u64,
    method_id: [u32; 8],
) -> Vec<u8> {
    let batch_proof_output = BatchProofCircuitOutput::<BitcoinSpec, [u8; 32]> {
        initial_state_root,
        final_state_root,
        last_l2_height,
        da_slot_hash: [0u8; 32].into(),
        prev_soft_confirmation_hash: [0u8; 32],
        final_soft_confirmation_hash: [0u8; 32],
        state_diff: BTreeMap::new(),
        sequencer_commitments_range: (0, 0),
        sequencer_da_public_key: [0u8; 32].to_vec(),
        sequencer_public_key: [0u8; 32].to_vec(),
        preproven_commitments: vec![],
    };
    let output_serialized = borsh::to_vec(&batch_proof_output).unwrap();

    let mut output_serialized_malformed = vec![1u8];
    output_serialized_malformed.extend(output_serialized.clone());

    let claim = MaybePruned::Value(ReceiptClaim::ok(
        method_id,
        output_serialized_malformed.clone(),
    ));
    let fake_receipt = FakeReceipt::new(claim);
    // Receipt with verifiable claim
    let receipt = Receipt::new(
        InnerReceipt::Fake(fake_receipt),
        output_serialized_malformed.clone(),
    );
    bincode::serialize(&receipt).unwrap()
}
