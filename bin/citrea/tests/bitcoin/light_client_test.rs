use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Address, U32, U64};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use bitcoin_da::helpers::parsers::{parse_relevant_transaction, ParsedTransaction, VerifyParsed};
use bitcoin_da::spec::RollupParams;
use bitcoin_da::utxo_manager::UtxoContext;
use bitcoin_da::verifier::BitcoinVerifier;
use bitcoincore_rpc::{Client, RpcApi};
use borsh::BorshDeserialize;
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_batch_prover::PartitionMode;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{
    BatchProverConfig, BitcoinConfig, CitreaMode, LightClientProverConfig, SequencerConfig,
    SequencerMempoolConfig, TestCaseConfig, TestCaseDockerConfig,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::{Restart, RestartPolicy};
use citrea_e2e::Result;
use citrea_fullnode::rpc::FullNodeRpcClient;
use citrea_light_client_prover::circuit::{
    AddSecurityCouncilMember, BatchProofMethodIdUpdate, RemoveBatchProofMethodId,
    RemoveSecurityCouncilMember, ReplaceSecurityCouncilMember, SetLcpToPreviousState,
    UpdateBatchProverDaPubKey, UpdateSecurityCouncilThreshold, UpdateSequencerDaPubKey,
};
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use citrea_primitives::compression::{compress_blob, decompress_blob};
use citrea_primitives::REVEAL_TX_PREFIX;
use rand::{thread_rng, Rng};
use reth_tasks::TaskManager;
use risc0_zkvm::{FakeReceipt, InnerReceipt, MaybePruned, ReceiptClaim};
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{
    AddSecurityCouncilMemberV1Body, BatchProofMethodIdBody, DaTxRequest, DaVerifier, DataOnDa,
    RemoveBatchProofMethodIdV1Body, RemoveSecurityCouncilMemberV1Body,
    ReplaceSecurityCouncilMemberV1Body, SecurityCouncilTx, SecurityCouncilTxType,
    SequencerCommitment, SetLcpToPreviousStateV1Body, UpdateBatchProverDaPubKeyV1Body,
    UpdateSecurityCouncilThresholdV1Body, UpdateSequencerDaPubKeyV1Body,
};
use sov_rollup_interface::rpc::BatchProofMethodIdRpcResponse;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::batch_proof::output::{BatchProofCircuitOutput, CumulativeStateDiff};
use sov_rollup_interface::zk::ProvingSessionInfo;
use sov_rollup_interface::Network;

use super::get_citrea_path;
use super::utils::PROVER_DA_PRIVATE_KEY;
use crate::bitcoin::utils::{
    create_valid_signatures, create_valid_signatures_with_wrong_domain,
    generate_initial_addresses_with_signers_from_pks, spawn_bitcoin_da_prover_service,
    spawn_bitcoin_da_sequencer_service, spawn_bitcoin_da_service, wait_for_prover_job,
    wait_for_zkproofs, DaServiceKeyKind, BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS,
};

pub const TEN_MINS: Duration = Duration::from_secs(10 * 60);

struct LightClientProvingTest {}

#[async_trait]
impl TestCase for LightClientProvingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            mode: CitreaMode::Dev,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 5,
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

    fn scan_l1_start_height() -> Option<u64> {
        Some(195)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        // publish max_l2_blocks_per_commitment confirmations
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, None).await?;

        // Finalize the DA block which contains the commitment tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height(None).await?;

        // Wait for batch prover to generate proof for commitment
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that commitment is queryable
        let commitments = batch_prover
            .client
            .http_client()
            .get_commitment_indices_by_l1(commitment_l1_height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), 1);

        // Ensure that batch proof is submitted to DA
        da.wait_mempool_len(2, None).await?;

        // Finalize the DA block which contains the batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let batch_proof_l1_height = da.get_finalized_height(None).await?;
        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?;
        assert!(lcp.is_some());

        let finalized_height = da.get_finalized_height(None).await?;
        // Wait for full node to see zkproofs
        let batch_proof = wait_for_zkproofs(
            full_node,
            finalized_height,
            Some(Duration::from_secs(7200)),
            1,
        )
        .await
        .unwrap();

        let light_client_proof = lcp.unwrap();
        assert_eq!(
            light_client_proof
                .light_client_proof_output
                .l2_state_root
                .to_vec(),
            batch_proof[0].proof_output.final_state_root()
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_proving() -> Result<()> {
    TestCaseRunner::new(LightClientProvingTest {})
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
            mode: CitreaMode::Dev,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 50,
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

    fn scan_l1_start_height() -> Option<u64> {
        Some(195)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let n_commitments = 2;

        // publish max_l2_blocks_per_commitment confirmations
        for _ in 0..n_commitments * max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(n_commitments * max_l2_blocks_per_commitment, None)
            .await?;

        // Wait for commitment txs to be submitted to DA
        da.wait_mempool_len((n_commitments * 2) as usize, Some(TEN_MINS))
            .await?;

        // Finalize the DA block which contains the commitment txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height(None).await?;

        // Wait for batch prover to see commitments
        batch_prover
            .wait_for_l1_height(commitment_l1_height, None)
            .await
            .unwrap();

        // There are two commitments, for each commitment generate a proof
        let job_ids = batch_prover
            .client
            .http_client()
            .prove(PartitionMode::OneByOne)
            .await
            .unwrap();
        assert_eq!(job_ids.len(), 2);

        // Wait for both prover jobs to finish
        let response_1 = wait_for_prover_job(batch_prover, job_ids[0], None)
            .await
            .unwrap();
        let response_2 = wait_for_prover_job(batch_prover, job_ids[1], None)
            .await
            .unwrap();
        assert_eq!(response_1.commitments.len(), 1);
        assert_eq!(response_2.commitments.len(), 1);

        // Finalize the DA block which contains the batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;
        // Wait for the full node to see all process verify and store all batch proofs
        full_node
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;
        let batch_proofs = wait_for_zkproofs(full_node, batch_proof_l1_height, None, 2).await?;
        assert_eq!(batch_proofs.len(), 2);

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await
            .unwrap();
        assert!(lcp.is_some());

        let light_client_proof = lcp.unwrap();
        assert_eq!(
            light_client_proof
                .light_client_proof_output
                .l2_state_root
                .to_vec(),
            batch_proofs[(n_commitments - 1) as usize]
                .proof_output
                .final_state_root()
        );

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(
            proven_height.height,
            light_client_proof
                .light_client_proof_output
                .last_l2_height
                .to::<u64>()
        );
        assert_eq!(
            proven_height.commitment_index,
            light_client_proof
                .light_client_proof_output
                .last_sequencer_commitment_index
                .to::<u32>()
        );

        // Generate another da block so we generate another lcp
        da.generate(1).await?;

        let last_finalized_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(last_finalized_height, Some(TEN_MINS))
            .await?;

        // Expect light client prover to have generated light client proof
        let lcp2 = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(last_finalized_height))
            .await
            .unwrap();
        assert!(lcp2.is_some());

        // Since there are no batch proofs the state root should be the same as the last one
        let light_client_proof2 = lcp2.unwrap();
        assert_eq!(
            light_client_proof2.light_client_proof_output.l2_state_root,
            light_client_proof.light_client_proof_output.l2_state_root
        );

        // The last processed l2 height should also be the same because there are no new batch proofs
        assert_eq!(
            light_client_proof2.light_client_proof_output.last_l2_height,
            light_client_proof.light_client_proof_output.last_l2_height
        );
        // The last processed l2 height should also be the same because there are no new batch proofs
        assert_eq!(
            light_client_proof2
                .light_client_proof_output
                .last_sequencer_commitment_index,
            light_client_proof
                .light_client_proof_output
                .last_sequencer_commitment_index
        );

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(
            proven_height.height,
            light_client_proof2
                .light_client_proof_output
                .last_l2_height
                .to::<u64>()
        );
        assert_eq!(
            proven_height.commitment_index,
            light_client_proof2
                .light_client_proof_output
                .last_sequencer_commitment_index
                .to::<u32>()
        );

        // Let's generate a new batch proof
        // publish max_l2_blocks_per_commitment confirmations
        let l2_height = sequencer.client.ledger_get_head_l2_block_height().await?;
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer
            .wait_for_l2_height(l2_height + max_l2_blocks_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, None).await?;

        // Finalize the DA block which contains the commitment txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height(None).await?;

        // Wait for batch prover to generate proofs for commitments
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await?;

        // There is one commitment, generate a single proof
        let job_ids = batch_prover
            .client
            .http_client()
            .prove(PartitionMode::OneByOne)
            .await
            .unwrap();

        let response = wait_for_prover_job(batch_prover, job_ids[0], None)
            .await
            .unwrap();
        assert_eq!(response.commitments.len(), 1);

        // Finalize the DA block which contains the batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;
        // Wait for the full node to see all process verify and store all batch proofs
        full_node
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;
        let batch_proofs = wait_for_zkproofs(full_node, batch_proof_l1_height, None, 1).await?;
        assert_eq!(batch_proofs.len(), 1);

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;

        // Expect light client prover to have generated light client proof
        let lcp3 = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await
            .unwrap();
        assert!(lcp3.is_some());

        let light_client_proof3 = lcp3.unwrap();
        assert_eq!(
            light_client_proof3
                .light_client_proof_output
                .l2_state_root
                .to_vec(),
            batch_proofs[0].proof_output.final_state_root()
        );

        assert_ne!(
            light_client_proof3.light_client_proof_output.last_l2_height,
            light_client_proof.light_client_proof_output.last_l2_height
        );
        assert_ne!(
            light_client_proof3
                .light_client_proof_output
                .last_sequencer_commitment_index,
            light_client_proof
                .light_client_proof_output
                .last_sequencer_commitment_index
        );

        assert_ne!(
            light_client_proof3.light_client_proof_output.l2_state_root,
            light_client_proof.light_client_proof_output.l2_state_root
        );

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(
            proven_height.height,
            light_client_proof3
                .light_client_proof_output
                .last_l2_height
                .to::<u64>()
        );
        assert_eq!(
            proven_height.commitment_index,
            light_client_proof3
                .light_client_proof_output
                .last_sequencer_commitment_index
                .to::<u32>()
        );

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

struct LightClientBatchProofMethodIdUpdateTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for LightClientBatchProofMethodIdUpdateTest {
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
            max_l2_blocks_per_commitment: 2,
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

    fn scan_l1_start_height() -> Option<u64> {
        Some(195)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            // Method id sender private key, can be any sender
            DaServiceKeyKind::Other(
                "79122E48DF1A002FB6584B2E94D0D50F95037416C82DAF280F21CD67D17D9077".to_string(),
            ),
            REVEAL_TX_PREFIX.to_vec(),
            None,
            None,
        )
        .await;

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        // publish max_l2_blocks_per_commitment confirmations
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, None).await?;

        // Finalize the DA block which contains the commitment tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height(None).await?;

        // Wait for batch prover to generate proof for commitment
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that commitment is queryable
        let commitments = batch_prover
            .client
            .http_client()
            .get_commitment_indices_by_l1(commitment_l1_height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), 1);

        // Ensure that batch proof is submitted to DA
        da.wait_mempool_len(2, None).await?;

        // Finalize the DA block which contains the batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let _lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?;

        let batch_proof_method_ids_before = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        // Verify the current batch proof method ids
        assert_eq!(
            batch_proof_method_ids_before,
            vec![BatchProofMethodIdRpcResponse {
                height: U64::from(0),
                method_id: citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID.into()
            }],
        );

        // Send BatchProofMethodId transaction to da
        let new_batch_proof_method_id = [1u32; 8];
        let method_id_body = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id,
            activation_l2_height: 210,
            nonce: 1,
        };

        let pk_bytes_arr: [[u8; 32]; 5] = BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS
            .map(|s| hex::decode(s).unwrap().try_into().unwrap());

        let (_initial_addresses, signers) =
            generate_initial_addresses_with_signers_from_pks(&pk_bytes_arr);

        let payload = BatchProofMethodIdUpdate::from(method_id_body.clone());

        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);

        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(method_id_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();

        // Ensure that method id tx is submitted to DA
        da.wait_mempool_len(2, None).await?;

        // Finalize the DA block which contains the method id tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let method_id_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process method id update
        light_client_prover
            .wait_for_l1_height(method_id_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that 1 l1 block before method id tx, still has the same batch proof method ids
        let _lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(method_id_l1_height - 1))
            .await?;

        // Assert that method ids are updated
        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        // Verify the current batch proof method ids
        assert_eq!(
            batch_proof_method_ids,
            vec![
                BatchProofMethodIdRpcResponse {
                    height: U64::from(0),
                    method_id: citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID.into()
                },
                BatchProofMethodIdRpcResponse {
                    height: U64::from(210),
                    method_id: new_batch_proof_method_id.into()
                }
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
        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert_eq!(
            batch_proof_method_ids,
            vec![
                BatchProofMethodIdRpcResponse {
                    height: U64::from(0),
                    method_id: citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID.into()
                },
                BatchProofMethodIdRpcResponse {
                    height: U64::from(210),
                    method_id: new_batch_proof_method_id.into()
                }
            ]
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_batch_proof_method_id_update() -> Result<()> {
    TestCaseRunner::new(LightClientBatchProofMethodIdUpdateTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct LightClientBatchProofMethodIdUpdateSecurityCouncilTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for LightClientBatchProofMethodIdUpdateSecurityCouncilTest {
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
            max_l2_blocks_per_commitment: 2,
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

    fn scan_l1_start_height() -> Option<u64> {
        Some(195)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            // Method id sender private key, can be any sender
            DaServiceKeyKind::Other(
                "79122E48DF1A002FB6584B2E94D0D50F95037416C82DAF280F21CD67D17D9077".to_string(),
            ),
            REVEAL_TX_PREFIX.to_vec(),
            None,
            None,
        )
        .await;

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let commitments = batch_prover
            .client
            .http_client()
            .get_commitment_indices_by_l1(commitment_l1_height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), 1);
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let _lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?;
        let batch_proof_method_ids_before = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert_eq!(
            batch_proof_method_ids_before,
            vec![BatchProofMethodIdRpcResponse {
                height: U64::from(0),
                method_id: citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID.into()
            }]
        );

        // --- CASE 1: All valid signatures and pubkeys ---
        let new_batch_proof_method_id = [2u32; 8];
        let method_id_body = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id,
            activation_l2_height: 220,
            nonce: 1,
        };
        let pk_bytes_arr: [[u8; 32]; 5] = BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS
            .map(|s| hex::decode(s).unwrap().try_into().unwrap());

        let (_initial_addresses, signers) =
            generate_initial_addresses_with_signers_from_pks(&pk_bytes_arr);

        let payload = BatchProofMethodIdUpdate::from(method_id_body.clone());

        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(
                        method_id_body.clone(),
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let method_id_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(method_id_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(batch_proof_method_ids
            .iter()
            .any(|x| x.method_id == new_batch_proof_method_id.into()));

        // --- CASE 2: Invalid signature (should be rejected) ---
        let new_batch_proof_method_id2 = [3u32; 8];
        let method_id_body2 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id2,
            activation_l2_height: 230,
            nonce: 2, // Correct nonce, but signature will be corrupted → rejected, nonce still consumed
        };

        let payload2 = BatchProofMethodIdUpdate::from(method_id_body2.clone());

        let mut signatures_with_index = create_valid_signatures(&signers, &payload2, 3);

        // Corrupt one signature
        signatures_with_index[0].0[0] ^= 0xFF;

        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(
                        method_id_body2.clone(),
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let method_id_l1_height2 = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(method_id_l1_height2, Some(TEN_MINS))
            .await
            .unwrap();
        let batch_proof_method_ids2 = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        // Should NOT contain new_batch_proof_method_id2
        assert!(!batch_proof_method_ids2
            .iter()
            .any(|x| x.method_id == new_batch_proof_method_id2.into()));

        // --- CASE 3: Test signature with duplicate pubkey index (should be rejected) ---
        let new_batch_proof_method_id3 = [4u32; 8];
        let method_id_body3 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id3,
            activation_l2_height: 240,
            nonce: 3, // Previous rejected msg consumed nonce
        };
        let payload3 = BatchProofMethodIdUpdate::from(method_id_body3.clone());

        let mut signatures_with_index = create_valid_signatures(&signers, &payload3, 3);

        // Corrupt one signature
        signatures_with_index[0].1 = signatures_with_index[2].1;
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(
                        method_id_body3.clone(),
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let method_id_l1_height3 = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(method_id_l1_height3, Some(TEN_MINS))
            .await
            .unwrap();
        let batch_proof_method_ids3 = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(!batch_proof_method_ids3
            .iter()
            .any(|x| x.method_id == new_batch_proof_method_id3.into()));

        // --- CASE 4: Test signature with pubkey index out of bounds (should be rejected) ---
        let new_batch_proof_method_id3 = [4u32; 8];
        let method_id_body3 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id3,
            activation_l2_height: 240,
            nonce: 4, // Previous rejected msgs consumed nonces
        };

        let payload3 = BatchProofMethodIdUpdate::from(method_id_body3.clone());

        let mut signatures_with_index = create_valid_signatures(&signers, &payload3, 3);

        // Corrupt one signature
        signatures_with_index[2].1 = 5; // out of bounds
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(
                        method_id_body3.clone(),
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let method_id_l1_height3 = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(method_id_l1_height3, Some(TEN_MINS))
            .await
            .unwrap();
        let batch_proof_method_ids3 = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(!batch_proof_method_ids3
            .iter()
            .any(|x| x.method_id == new_batch_proof_method_id3.into()));

        // --- CASE 4: Test signature with pubkey index Swapped (should be rejected) ---
        let new_batch_proof_method_id3 = [4u32; 8];
        let method_id_body3 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id3,
            activation_l2_height: 240,
            nonce: 5, // Previous rejected msgs consumed nonces
        };

        let payload3 = BatchProofMethodIdUpdate::from(method_id_body3.clone());

        let mut signatures_with_index = create_valid_signatures(&signers, &payload3, 3);

        // Swap pubkey indices of the first and last signature
        // This should be rejected as now signatures will point to wrong pubkeys
        let tmp = signatures_with_index[0].1;
        signatures_with_index[0].1 = signatures_with_index[2].1;
        signatures_with_index[2].1 = tmp;

        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(
                        method_id_body3.clone(),
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let method_id_l1_height3 = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(method_id_l1_height3, Some(TEN_MINS))
            .await
            .unwrap();
        let batch_proof_method_ids3 = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(!batch_proof_method_ids3
            .iter()
            .any(|x| x.method_id == new_batch_proof_method_id3.into()));

        // Case 5: Test with wrong network (should be rejected)
        // Sign with Mainnet domain instead of Nightly - signature verification should fail
        let new_batch_proof_method_id4 = [5u32; 8];
        let method_id_body4 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id4,
            activation_l2_height: 250,
            nonce: 6, // Previous rejected msgs consumed nonces
        };

        let payload4 = BatchProofMethodIdUpdate::from(method_id_body4.clone());
        let signatures_with_index =
            create_valid_signatures_with_wrong_domain(&signers, &payload4, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(
                        method_id_body4.clone(),
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let method_id_l1_height4 = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(method_id_l1_height4, Some(TEN_MINS))
            .await
            .unwrap();
        let batch_proof_method_ids4 = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(!batch_proof_method_ids4
            .iter()
            .any(|x| x.method_id == new_batch_proof_method_id4.into()));

        // Case 6: Test signature indexes not ascending order (should be rejected)
        let new_batch_proof_method_id5 = [6u32; 8];
        let method_id_body5 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id5,
            activation_l2_height: 260,
            nonce: 7, // Previous rejected msgs consumed nonces
        };
        let payload5 = BatchProofMethodIdUpdate::from(method_id_body5.clone());
        let mut signatures_with_index = create_valid_signatures(&signers, &payload5, 3);
        // Make indexes not in ascending order
        signatures_with_index.swap(0, 2);

        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(
                        method_id_body5.clone(),
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let method_id_l1_height5 = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(method_id_l1_height5, Some(TEN_MINS))
            .await
            .unwrap();
        let batch_proof_method_ids5 = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(!batch_proof_method_ids5
            .iter()
            .any(|x| x.method_id == new_batch_proof_method_id5.into()));

        // --- CASE 7: Replay attack - reuse nonce=1 which was already consumed (should be rejected) ---
        let replay_method_id = [7u32; 8];
        let replay_body = BatchProofMethodIdBody {
            method_id: replay_method_id,
            activation_l2_height: 270,
            nonce: 1, // Already consumed by CASE 1
        };
        let replay_payload = BatchProofMethodIdUpdate::from(replay_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &replay_payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(replay_body.clone()),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let replay_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(replay_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let replay_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(!replay_method_ids
            .iter()
            .any(|x| x.method_id == replay_method_id.into()));

        // --- CASE 8: Lower nonce=0 (should be rejected) ---
        let lower_nonce_method_id = [8u32; 8];
        let lower_nonce_body = BatchProofMethodIdBody {
            method_id: lower_nonce_method_id,
            activation_l2_height: 280,
            nonce: 0, // Lower than current nonce (1)
        };
        let lower_nonce_payload = BatchProofMethodIdUpdate::from(lower_nonce_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &lower_nonce_payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(
                        lower_nonce_body.clone(),
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let lower_nonce_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(lower_nonce_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let lower_nonce_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(!lower_nonce_method_ids
            .iter()
            .any(|x| x.method_id == lower_nonce_method_id.into()));

        // --- CASE 9: Skipped nonce=3 (should be rejected, expected nonce=2) ---
        let skipped_nonce_method_id = [9u32; 8];
        let skipped_nonce_body = BatchProofMethodIdBody {
            method_id: skipped_nonce_method_id,
            activation_l2_height: 290,
            nonce: 3, // Skipped nonce=2
        };
        let skipped_nonce_payload = BatchProofMethodIdUpdate::from(skipped_nonce_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &skipped_nonce_payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(
                        skipped_nonce_body.clone(),
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let skipped_nonce_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(skipped_nonce_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let skipped_nonce_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(!skipped_nonce_method_ids
            .iter()
            .any(|x| x.method_id == skipped_nonce_method_id.into()));

        // --- CASE 10: Correct nonce=2 after replay attempts (should be accepted) ---
        let correct_nonce_method_id = [10u32; 8];
        let correct_nonce_body = BatchProofMethodIdBody {
            method_id: correct_nonce_method_id,
            activation_l2_height: 300,
            nonce: 8, // Correct next nonce (failed msgs consumed nonces 2-7)
        };
        let correct_nonce_payload = BatchProofMethodIdUpdate::from(correct_nonce_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &correct_nonce_payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(
                        correct_nonce_body.clone(),
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let correct_nonce_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(correct_nonce_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let correct_nonce_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(correct_nonce_method_ids
            .iter()
            .any(|x| x.method_id == correct_nonce_method_id.into()));

        // At this point we have 3 method IDs:
        // index 0: (0, initial_method_id)
        // index 1: (220, [2;8]) from CASE 1
        // index 2: (300, [10;8]) from CASE 10
        // Current nonce: 8

        // --- CASE 11: Remove method id with wrong method_id field (should be rejected) ---
        let remove_wrong_id_body = RemoveBatchProofMethodIdV1Body {
            method_id_index: 1,
            batch_proof_method_id: [99u32; 8], // Wrong — actual is [2;8]
            l2_activation_height: 220,
            nonce: 9,
        };
        let remove_wrong_id_payload = RemoveBatchProofMethodId::from(remove_wrong_id_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &remove_wrong_id_payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::RemoveBatchProofMethodIdV1(
                        remove_wrong_id_body,
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let remove_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(remove_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let method_ids_after_wrong = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        // Still 3 — wrong method_id field rejected
        assert_eq!(method_ids_after_wrong.len(), 3);

        // --- CASE 12: Remove method id with wrong activation height (should be rejected) ---
        let remove_wrong_height_body = RemoveBatchProofMethodIdV1Body {
            method_id_index: 1,
            batch_proof_method_id: new_batch_proof_method_id, // Correct [2;8]
            l2_activation_height: 999,                        // Wrong — actual is 220
            nonce: 10,                                        // CASE 11 consumed nonce
        };
        let remove_wrong_height_payload =
            RemoveBatchProofMethodId::from(remove_wrong_height_body.clone());
        let signatures_with_index =
            create_valid_signatures(&signers, &remove_wrong_height_payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::RemoveBatchProofMethodIdV1(
                        remove_wrong_height_body,
                    ),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let remove_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(remove_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let method_ids_after_wrong_h = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert_eq!(method_ids_after_wrong_h.len(), 3);

        // --- CASE 13: Remove method id with out-of-bounds index (should be rejected) ---
        let remove_oob_body = RemoveBatchProofMethodIdV1Body {
            method_id_index: 10, // Only 3 entries
            batch_proof_method_id: [0u32; 8],
            l2_activation_height: 0,
            nonce: 11,
        };
        let remove_oob_payload = RemoveBatchProofMethodId::from(remove_oob_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &remove_oob_payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::RemoveBatchProofMethodIdV1(remove_oob_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let remove_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(remove_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let method_ids_after_oob = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert_eq!(method_ids_after_oob.len(), 3);

        // --- CASE 14: Valid remove of method id at index 1 (should be accepted) ---
        let remove_valid_body = RemoveBatchProofMethodIdV1Body {
            method_id_index: 1,
            batch_proof_method_id: new_batch_proof_method_id, // [2;8]
            l2_activation_height: 220,
            nonce: 12, // Correct — previous removes consumed nonces 9-11
        };
        let remove_valid_payload = RemoveBatchProofMethodId::from(remove_valid_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &remove_valid_payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::RemoveBatchProofMethodIdV1(remove_valid_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let remove_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(remove_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let method_ids_after_valid_remove = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        // Down to 2 — the [2;8] method id was removed
        assert_eq!(method_ids_after_valid_remove.len(), 2);
        assert!(!method_ids_after_valid_remove
            .iter()
            .any(|x| x.method_id == new_batch_proof_method_id.into()));
        assert!(method_ids_after_valid_remove
            .iter()
            .any(|x| x.method_id == correct_nonce_method_id.into()));

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_batch_proof_method_id_update_security_council() -> Result<()> {
    TestCaseRunner::new(LightClientBatchProofMethodIdUpdateSecurityCouncilTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct LightClientUnverifiableBatchProofTest {
    task_manager: TaskManager,
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

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_prover_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_sequencer_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
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

        assert!(batch_proof_method_ids.len() == 1);

        let fork2_height: u64 = batch_proof_method_ids[0].height.to();
        let l1_hash = da.get_block_hash(finalized_height).await?;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: fork2_height + 1,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment_2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: fork2_height + 2,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment_2.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment_3 = SequencerCommitment {
            merkle_root: [3u8; 32],
            index: 3,
            l2_end_block_number: fork2_height + 3,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment_3.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment_4 = SequencerCommitment {
            merkle_root: [4u8; 32],
            index: 4,
            l2_end_block_number: fork2_height + 4,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment_4.clone()),
                1.0,
            )
            .await
            .unwrap();

        da.wait_mempool_len(8, None).await?;

        // Finalize the DA block which contains the seq comm txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let verifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            genesis_state_root,
            fork2_height + 1,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_batch_proof), 1.0)
            .await
            .unwrap();

        let verifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [2u8; 32],
            fork2_height + 3,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment_3.clone()],
            Some(fake_sequencer_commitment_2.serialize_and_calculate_sha_256()),
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_batch_proof), 1.0)
            .await
            .unwrap();

        // Expect unparsable journal to be skipped
        let unparsable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [3u8; 32],
            fork2_height + 4,
            batch_proof_method_ids[0].method_id.into(),
            None,
            true,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment_4.clone()],
            Some(fake_sequencer_commitment_3.serialize_and_calculate_sha_256()),
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(unparsable_batch_proof), 1.0)
            .await
            .unwrap();

        let verifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            fork2_height + 2,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment_2.clone()],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_batch_proof), 1.0)
            .await
            .unwrap();

        // Give it a random method id to make it unverifiable
        let random_method_id = [1u32; 8];
        let unverifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [3u8; 32],
            fork2_height + 4,
            random_method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment_4.clone()],
            Some(fake_sequencer_commitment_3.serialize_and_calculate_sha_256()),
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(unverifiable_batch_proof), 1.0)
            .await
            .unwrap();

        // Ensure that all four batch proofs is submitted to DA
        da.wait_mempool_len(10, None).await?;

        // Finalize the DA block which contains the batch proof txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process unverifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof without panic but it should not have updated the state root
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The unverifiable batch proof and malformed journal batch proof should not have updated the state root or the last l2 height
        assert_eq!(lcp_output.l2_state_root, [3u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(fork2_height + 3));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(3));

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_unverifiable_batch_proof() -> Result<()> {
    TestCaseRunner::new(LightClientUnverifiableBatchProofTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct VerifyChunkedTxsInLightClient {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for VerifyChunkedTxsInLightClient {
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

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
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
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_prover_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_sequencer_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_last_l2_height: u64 = 10;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: proof_last_l2_height,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: proof_last_l2_height * 2,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment2.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment3 = SequencerCommitment {
            merkle_root: [3u8; 32],
            index: 3,
            l2_end_block_number: proof_last_l2_height * 3,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment3.clone()),
                1.0,
            )
            .await
            .unwrap();

        da.wait_mempool_len(6, None).await?;

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

        assert!(batch_proof_method_ids.len() == 1);

        // Even though the state diff is 100kb the proof will be 200kb because the fake receipt claim also has the journal
        // But the compressed size will go down to 100kb
        let state_diff_100kb = create_random_state_diff(100);

        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 100kb (compressed size) batch proof (not 1mb because if testing feature is enabled max body size is 39700), this batch proof will consist of 3 chunk and 1 aggregate transactions because 100kb/40kb = 3 chunks
        let verifiable_100kb_batch_proof = create_serialized_fake_receipt_batch_proof(
            genesis_state_root,
            proof_last_l2_height,
            batch_proof_method_ids[0].method_id.into(),
            Some(state_diff_100kb.clone()),
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_100kb_batch_proof), 1.0)
            .await
            .unwrap();

        // In total 3 chunks 1 aggregate with all of them having reveal and commit txs we should have 8 txs in mempool
        da.wait_mempool_len(8, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the batch proof txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Make sure all of them are in the block
        let mempool = da.get_raw_mempool().await?;
        assert!(mempool.is_empty());

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process verifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The batch proof should have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(proof_last_l2_height));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        // Now generate another proof but this time:
        // Have 4 chunks and 1 aggregate
        // First two chunks will should be in block n
        // Last two chunks should be in block n+1
        // And the aggregate should be in block n+2
        // After the block n+2 is processed we should see the state root updated
        let state_diff_130kb = create_random_state_diff(130);

        let finalized_height = da.get_finalized_height(None).await?;
        // finalized_height - 3 does not serve any purpose beyond just trying a different number
        // it could be finalized_height or finalized_height - x (x any number)
        let l1_hash = da.get_block_hash(finalized_height - 3).await?;

        let verifiable_130kb_batch_proof = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            proof_last_l2_height * 2,
            batch_proof_method_ids[0].method_id.into(),
            Some(state_diff_130kb),
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment2.clone()],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );

        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_130kb_batch_proof), 1.0)
            .await
            .unwrap();

        // In total 4 chunks 1 aggregate with all of them having reveal and commit txs we should have 10 txs in mempool
        da.wait_mempool_len(10, Some(TEN_MINS)).await?;

        // Get txs from mempool
        let txs = da.get_raw_mempool().await?;

        // // Get the first four txs ( first two chunks )
        let first_two_chunks = txs[0..4]
            .iter()
            .map(|txid| txid.to_string())
            .collect::<Vec<_>>();
        let last_two_chunks = txs[4..8]
            .iter()
            .map(|txid| txid.to_string())
            .collect::<Vec<_>>();
        let aggregate = txs[8..10]
            .iter()
            .map(|txid| txid.to_string())
            .collect::<Vec<_>>();

        let addr = da
            .get_new_address(None, None)
            .await?
            .assume_checked()
            .to_string();

        da.generate_block(addr.clone(), first_two_chunks).await?;
        // First two chunks should be in block n
        da.wait_mempool_len(6, Some(TEN_MINS)).await?;

        da.generate_block(addr.clone(), last_two_chunks).await?;
        // Last two chunks should be in block n+1
        da.wait_mempool_len(2, None).await?;

        da.generate_block(addr.clone(), aggregate).await?;
        // Aggregate should be in block n+2
        let mempool = da.get_raw_mempool().await?;
        assert!(mempool.is_empty());

        // Finalize the DA block which contains the aggregate txs
        da.generate(DEFAULT_FINALITY_DEPTH - 1).await?;

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process verifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp_first_chunks = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height - 2))
            .await?;

        let lcp_output = lcp_first_chunks.unwrap().light_client_proof_output;

        // The batch proof should not have updated the state root and the last l2 height because these are only the chunks
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(proof_last_l2_height));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        let lcp_last_chunks = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height - 1))
            .await?;

        let lcp_output = lcp_last_chunks.unwrap().light_client_proof_output;

        // The batch proof should not have updated the state root and the last l2 height because these are only the chunks
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(proof_last_l2_height));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        // Expect light client prover to have generated light client proof
        let lcp_aggregate = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?;

        let lcp_output = lcp_aggregate.unwrap().light_client_proof_output;

        // The batch proof should have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, [2u8; 32]);
        assert_eq!(
            lcp_output.last_l2_height,
            U64::from(proof_last_l2_height * 2)
        );
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(2));

        let random_method_id = [1u32; 8];

        // This should result in 3 chunks and 1 aggregate tx
        let unverifiable_100kb_batch_proof = create_serialized_fake_receipt_batch_proof(
            [2u8; 32],
            proof_last_l2_height * 3,
            random_method_id,
            Some(state_diff_100kb),
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment3],
            Some(fake_sequencer_commitment2.serialize_and_calculate_sha_256()),
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::ZKProof(unverifiable_100kb_batch_proof),
                1.0,
            )
            .await
            .unwrap();

        // In total 3 chunks 1 aggregate with all of them having reveal and commit txs we should have 8 txs in mempool
        da.wait_mempool_len(8, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the batch proof txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Make sure all of them are in the block
        let mempool = da.get_raw_mempool().await?;
        assert!(mempool.is_empty());

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process verifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The batch proof should NOT have updated the state root and the last l2 height
        // Because it is not verified
        assert_eq!(lcp_output.l2_state_root, [2u8; 32]);
        assert_eq!(
            lcp_output.last_l2_height,
            U64::from(proof_last_l2_height * 2)
        );
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(2));

        Ok(())
    }
}

#[tokio::test]
async fn test_verify_chunked_txs_in_light_client() -> Result<()> {
    TestCaseRunner::new(VerifyChunkedTxsInLightClient {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct UnchainedBatchProofsTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for UnchainedBatchProofsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 164,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(164)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_prover_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_sequencer_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: 100,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: 200,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment2.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment3 = SequencerCommitment {
            merkle_root: [3u8; 32],
            index: 3,
            l2_end_block_number: 300,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment3.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment4 = SequencerCommitment {
            merkle_root: [4u8; 32],
            index: 4,
            l2_end_block_number: 400,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment4.clone()),
                1.0,
            )
            .await
            .unwrap();

        da.wait_mempool_len(8, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let start_l1_height = da.get_finalized_height(None).await?;

        light_client_prover.wait_for_l1_height(170, None).await?;

        let initial_lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(170))
            .await?
            .unwrap();

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        let method_id = batch_proof_method_ids[0].method_id.into();
        let genesis_root = initial_lcp.light_client_proof_output.l2_state_root;
        let l1_hash = da.get_block_hash(171).await?;

        // put 3 bp in a block
        // first one is chained, second one is unchained, third one can be chained to the second one
        // on the next block, we put another bp that can be chained to the first one in the previous block
        // and the second-third will chain to this one

        let bp1 = create_serialized_fake_receipt_batch_proof(
            genesis_root,
            100,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        let bp2 = create_serialized_fake_receipt_batch_proof(
            [2u8; 32],
            300,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment3.clone()],
            Some(fake_sequencer_commitment2.serialize_and_calculate_sha_256()),
        );

        let bp3 = create_serialized_fake_receipt_batch_proof(
            [3u8; 32],
            400,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment4.clone()],
            Some(fake_sequencer_commitment3.serialize_and_calculate_sha_256()),
        );

        let bp4 = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            200,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment2.clone()],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp1), 1.0)
            .await
            .unwrap();

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp2), 1.0)
            .await
            .unwrap();

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp3), 1.0)
            .await
            .unwrap();

        da.wait_mempool_len(6, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        light_client_prover
            .wait_for_l1_height(start_l1_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(
                start_l1_height + DEFAULT_FINALITY_DEPTH,
            ))
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(100));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp4), 1.0)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        light_client_prover
            .wait_for_l1_height(start_l1_height + 2 * DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(
                start_l1_height + 2 * DEFAULT_FINALITY_DEPTH,
            ))
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        assert_eq!(lcp_output.l2_state_root, [4u8; 32]);
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(4));

        Ok(())
    }
}

#[tokio::test]
async fn test_unchained_batch_proofs_in_light_client() -> Result<()> {
    TestCaseRunner::new(UnchainedBatchProofsTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct UnknownL1HashBatchProofTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for UnknownL1HashBatchProofTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 165,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
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
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_prover_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;
        let sequencer_bitcoin_da_service = spawn_bitcoin_da_sequencer_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: 100,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1.0,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let start_l1_height = da.get_finalized_height(None).await?;

        light_client_prover.wait_for_l1_height(170, None).await?;

        let initial_lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(170))
            .await?
            .unwrap();

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        let method_id = batch_proof_method_ids[0].method_id.into();
        let genesis_root = initial_lcp.light_client_proof_output.l2_state_root;
        let mut l1_hash = da.get_block_hash(171).await?.to_raw_hash().to_byte_array();

        // make it unknown
        l1_hash[0] = l1_hash[0].wrapping_add(1);

        let bp = create_serialized_fake_receipt_batch_proof(
            genesis_root,
            100,
            method_id,
            None,
            false,
            l1_hash,
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp), 1.0)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        light_client_prover
            .wait_for_l1_height(start_l1_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(
                start_l1_height + DEFAULT_FINALITY_DEPTH,
            ))
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        // batch proof with unknown L1 hash was ignored
        assert_eq!(lcp_output.l2_state_root, genesis_root);
        assert_eq!(lcp_output.last_l2_height, U64::from(0));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(0));

        Ok(())
    }
}

#[tokio::test]
async fn test_unknown_l1_hash_batch_proof_in_light_client() -> Result<()> {
    TestCaseRunner::new(UnknownL1HashBatchProofTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct ChainProofByCommitmentIndex {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for ChainProofByCommitmentIndex {
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

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
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
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_prover_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_sequencer_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: 100,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: 100 * 2,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment2.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment3 = SequencerCommitment {
            merkle_root: [3u8; 32],
            index: 3,
            l2_end_block_number: 100 * 3,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment3.clone()),
                1.0,
            )
            .await
            .unwrap();

        da.wait_mempool_len(6, None).await?;

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
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        // Get initial method ids and genesis state root
        let method_ids = batch_proof_method_ids;
        let genesis_state_root = lcp_output.l2_state_root;

        assert!(method_ids.len() == 1);

        let l1_hash = da.get_block_hash(finalized_height).await?;

        let bp = create_serialized_fake_receipt_batch_proof(
            genesis_state_root,
            200,
            method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![
                fake_sequencer_commitment.clone(),
                fake_sequencer_commitment2.clone(),
            ],
            None,
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp), 1.0)
            .await
            .unwrap();

        let bp = create_serialized_fake_receipt_batch_proof(
            fake_sequencer_commitment.merkle_root, // using the roots as state roots in this test
            300,
            method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![
                fake_sequencer_commitment2.clone(),
                fake_sequencer_commitment3.clone(),
            ],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp), 1.0)
            .await
            .unwrap();

        da.wait_mempool_len(4, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Make sure all of them are in the block
        let mempool = da.get_raw_mempool().await?;
        assert!(mempool.is_empty());

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process verifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The batch proof should have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, [3u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(300));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(3));

        Ok(())
    }
}

#[tokio::test]
async fn test_chain_proof_by_commitment_index() -> Result<()> {
    TestCaseRunner::new(ChainProofByCommitmentIndex {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct ProofWithMissingCommitment {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for ProofWithMissingCommitment {
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

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
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
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_prover_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: 100,
        };

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
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        // Get initial method ids and genesis state root
        let method_ids = batch_proof_method_ids;
        let genesis_state_root = lcp_output.l2_state_root;

        assert!(method_ids.len() == 1);

        let l1_hash = da.get_block_hash(finalized_height).await?;

        let bp = create_serialized_fake_receipt_batch_proof(
            genesis_state_root,
            100,
            method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp), 1.0)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Make sure all of them are in the block
        let mempool = da.get_raw_mempool().await?;
        assert!(mempool.is_empty());

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process verifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The batch proof should have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, genesis_state_root);
        assert_eq!(lcp_output.last_l2_height, U64::from(0));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(0));

        Ok(())
    }
}

#[tokio::test]
async fn test_proof_with_missing_commitment_is_discarded() -> Result<()> {
    TestCaseRunner::new(ProofWithMissingCommitment {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct ProofAndCommitmentWithWrongDaPubkey {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for ProofAndCommitmentWithWrongDaPubkey {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 164,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(164)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let batch_prover_bitcoin_da_service = spawn_bitcoin_da_prover_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_sequencer_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let malicious_bitcoin_da_service = spawn_bitcoin_da_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Other(
                "1212121212121212121212121212121212121212121212121212121212121212".to_string(),
            ),
            REVEAL_TX_PREFIX.to_vec(),
            None,
            None,
        )
        .await;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: 100,
        };

        let _ = malicious_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1.0,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let start_l1_height = da.get_finalized_height(None).await?;

        light_client_prover.wait_for_l1_height(170, None).await?;

        let initial_lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(170))
            .await?
            .unwrap();

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        let method_id = batch_proof_method_ids[0].method_id.into();
        let genesis_root = initial_lcp.light_client_proof_output.l2_state_root;
        let l1_hash = da.get_block_hash(171).await?;

        // put 1 bp in a block with wrong commitment da pub key, this proof should not transition because we should not have the commitment
        let bp1 = create_serialized_fake_receipt_batch_proof(
            genesis_root,
            100,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        batch_prover_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp1), 1.0)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        light_client_prover
            .wait_for_l1_height(start_l1_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(
                start_l1_height + DEFAULT_FINALITY_DEPTH,
            ))
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        // Should not have transitioned because the commitment should not have made it in.
        assert_eq!(lcp_output.l2_state_root, genesis_root);
        assert_eq!(lcp_output.last_l2_height, U64::from(0));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(0));

        // Now send with the correct da service
        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1.0,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // put 1 bp in a block with wrong commitment da pub key, this proof should not transition because we should not have the commitment
        let bp1 = create_serialized_fake_receipt_batch_proof(
            genesis_root,
            100,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        batch_prover_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp1), 1.0)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(
                finalized_height + DEFAULT_FINALITY_DEPTH,
            ))
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        // Should have transitioned because the commitment now has the correct da pub key.
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(100));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        // Now send batch proof with wrong da pub key and expect it to not transition
        let fake_sequencer_commitment2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: 200,
        };

        // Now send with the correct da service
        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment2.clone()),
                1.0,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // put 1 bp in a block with wrong batch prover da pub key, this proof should not transition because it should not be accepted
        let bp2 = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            200,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment2.clone()],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );

        malicious_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp2.clone()), 1.0)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(
                finalized_height + DEFAULT_FINALITY_DEPTH,
            ))
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        // Should not have transitioned because the commitment should not have made it in.
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(100));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        // Now send batch proof with the correct da pub key and expect it to transition
        batch_prover_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp2.clone()), 1.0)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        // Should have transitioned because the proof should have made it in.
        assert_eq!(lcp_output.l2_state_root, [2u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(200));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(2));

        Ok(())
    }
}

#[tokio::test]
async fn test_proof_and_commitment_with_wrong_da_pubkey() -> Result<()> {
    TestCaseRunner::new(ProofAndCommitmentWithWrongDaPubkey {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct ProofWithWrongPreviousCommitmentHash {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for ProofWithWrongPreviousCommitmentHash {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 164,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
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
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let batch_prover_bitcoin_da_service = spawn_bitcoin_da_prover_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_sequencer_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
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

        assert!(batch_proof_method_ids.len() == 1);

        let fork2_height: u64 = batch_proof_method_ids[0].height.to();

        let l1_hash = da.get_block_hash(finalized_height).await?;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: fork2_height + 1,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1.0,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment_2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: fork2_height + 2,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment_2.clone()),
                1.0,
            )
            .await
            .unwrap();

        da.wait_mempool_len(4, None).await?;

        // Finalize the DA block which contains the seq comm txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let verifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            genesis_state_root,
            fork2_height + 1,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );
        let _ = batch_prover_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_batch_proof), 1.0)
            .await
            .unwrap();

        // Finalize the first proof
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;
        // The batch proof should have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(fork2_height + 1));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        let wrong_prev_hash_batch_proof = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            fork2_height + 2,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment_2.clone()],
            // Some random hash
            Some(
                hex::decode("696D616D68617469706C65726B61706174696C73696E6572646F67616E6F6331")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
        );
        let _ = batch_prover_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(wrong_prev_hash_batch_proof), 1.0)
            .await
            .unwrap();

        // Finalize the second proof
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;
        // The batch proof should not have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(fork2_height + 1));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        let correct_prev_hash_proof = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            fork2_height + 2,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment_2.clone()],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );
        let _ = batch_prover_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(correct_prev_hash_proof), 1.0)
            .await
            .unwrap();

        // Finalize the correct second proof
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;
        // The batch proof should have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, [2u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(fork2_height + 2));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(2));

        Ok(())
    }
}

#[tokio::test]
async fn test_proof_with_wrong_previous_commitment_hash() -> Result<()> {
    TestCaseRunner::new(ProofWithWrongPreviousCommitmentHash {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

pub(crate) fn create_random_state_diff(size_in_kb: u64) -> BTreeMap<Arc<[u8]>, Option<Arc<[u8]>>> {
    let mut rng = thread_rng();
    let mut map = BTreeMap::new();
    let mut total_size: u64 = 0;

    // Convert size to bytes
    let size_in_bytes = size_in_kb * 1024;

    while total_size < size_in_bytes {
        // Generate a random 32-byte key
        let key: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();

        // Randomly decide if the value is `None` or a `Vec<u8>` of random length
        let value: Option<Vec<u8>> = if rng.gen_bool(0.1) {
            None
        } else {
            let value_size: usize = rng.gen_range(1..=2048);
            Some((0..value_size).map(|_| rng.gen::<u8>()).collect())
        };

        // Calculate the size of the key and value
        let key_size = key.len() as u64;
        let value_size = match &value {
            Some(v) => v.len() as u64 + 1,
            None => 1,
        };

        // Add to the map
        map.insert(
            Arc::from(key.into_boxed_slice()),
            value.map(|v| Arc::from(v.into_boxed_slice())),
        );

        // Update the total size
        total_size += key_size + value_size;
    }

    map
}

#[allow(clippy::too_many_arguments)]
pub fn create_serialized_fake_receipt_batch_proof(
    initial_state_root: [u8; 32],
    last_l2_height: u64,
    method_id: [u32; 8],
    state_diff: Option<CumulativeStateDiff>,
    malformed_journal: bool,
    last_l1_hash_on_bitcoin_light_client_contract: [u8; 32],
    sequencer_commitments: Vec<SequencerCommitment>,
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
    state_roots.extend(sequencer_commitments.iter().map(|c| c.merkle_root));

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

struct UndecompressableBlobTest {
    task_manager: TaskManager,
}

impl UndecompressableBlobTest {
    fn verify_complete_is_non_decompressable(tx: &bitcoin::Transaction) -> bool {
        if let Ok(ParsedTransaction::Complete(complete)) = parse_relevant_transaction(tx) {
            let Ok(data) = DataOnDa::try_from_slice(complete.body()) else {
                panic!("Failed to parse complete data");
            };

            let DataOnDa::Complete(compressed_zk_proof) = data else {
                panic!("Expected complete data type");
            };
            decompress_blob(&compressed_zk_proof).is_err()
        } else {
            false
        }
    }

    fn verify_chunked_is_non_decompressable(block: &bitcoin::Block) -> bool {
        let mut complete_proof = Vec::new();

        for tx in &block.txdata {
            if let Ok(ParsedTransaction::Aggregate(aggregate)) = parse_relevant_transaction(tx) {
                complete_proof.extend_from_slice(aggregate.body());
            }
        }

        decompress_blob(&complete_proof).is_err()
    }

    async fn send_complete_tx(client: &Client) -> anyhow::Result<(Txid, Txid)> {
        use std::str::FromStr;

        use bitcoin::secp256k1::SecretKey;
        use bitcoin_da::helpers::builders::body_builders::{create_inscription_type_0, DaTxs};

        let da_private_key = SecretKey::from_str(PROVER_DA_PRIVATE_KEY).unwrap();
        let change_address = client.get_new_address(None, None).await?.assume_checked();
        let utxos = client
            .list_unspent(None, None, None, None, None)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();

        let compressed_data = compress_blob(&[1u8; 64]).unwrap();
        let mut malformed_undecompressable_data = vec![0u8];
        malformed_undecompressable_data.extend_from_slice(&compressed_data);

        let body = borsh::to_vec(&DataOnDa::Complete(malformed_undecompressable_data)).unwrap();
        let DaTxs::Complete { commit, reveal } = create_inscription_type_0(
            body,
            &da_private_key,
            UtxoContext {
                prev_utxo: None,
                available_utxos: utxos,
            },
            change_address,
            1.0,
            1.0,
            bitcoin::Network::Regtest,
            REVEAL_TX_PREFIX,
        )?
        else {
            panic!("Unexpected result type")
        };

        let signed_raw_commit_tx = client
            .sign_raw_transaction_with_wallet(&commit, None, None)
            .await?;

        Ok((
            client
                .send_raw_transaction(&signed_raw_commit_tx.hex)
                .await?,
            client
                .send_raw_transaction(&bitcoin::consensus::encode::serialize(&reveal.tx))
                .await?,
        ))
    }

    async fn send_chunked_tx(client: &Client) -> anyhow::Result<Vec<Txid>> {
        use std::str::FromStr;

        use bitcoin::consensus::encode;
        use bitcoin::secp256k1::SecretKey;
        use bitcoin_da::helpers::builders::body_builders::{create_inscription_type_1, DaTxs};
        use bitcoincore_rpc::json::SignRawTransactionInput;

        let da_private_key = SecretKey::from_str(PROVER_DA_PRIVATE_KEY).unwrap();
        let change_address = client.get_new_address(None, None).await?.assume_checked();
        let utxos = client
            .list_unspent(None, None, None, None, None)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();

        let mut chunks = vec![];
        for _ in 0..2 {
            let data = DataOnDa::Chunk(vec![1; 64]);
            let blob = borsh::to_vec(&data).unwrap();
            chunks.push(blob)
        }

        let DaTxs::Chunked {
            commit_chunks,
            reveal_chunks,
            commit,
            reveal,
        } = create_inscription_type_1(
            chunks,
            &da_private_key,
            UtxoContext {
                available_utxos: utxos,
                prev_utxo: None,
            },
            change_address,
            2.0,
            2.0,
            bitcoin::Network::Regtest,
            REVEAL_TX_PREFIX,
        )?
        else {
            panic!("Wrong DaTxs kind");
        };

        let mut raw_txs = Vec::new();

        let all_tx_map = commit_chunks
            .iter()
            .chain(reveal_chunks.iter())
            .chain([&commit, &reveal.tx].into_iter())
            .map(|tx| (tx.compute_txid(), tx.clone()))
            .collect::<HashMap<_, _>>();

        for (commit, reveal) in commit_chunks.into_iter().zip(reveal_chunks) {
            let mut inputs = vec![];

            for input in commit.input.iter() {
                if let Some(entry) = all_tx_map.get(&input.previous_output.txid) {
                    inputs.push(SignRawTransactionInput {
                        txid: input.previous_output.txid,
                        vout: input.previous_output.vout,
                        script_pub_key: entry.output[input.previous_output.vout as usize]
                            .script_pubkey
                            .clone(),
                        redeem_script: None,
                        amount: Some(entry.output[input.previous_output.vout as usize].value),
                    });
                }
            }

            let signed_raw_commit_tx = client
                .sign_raw_transaction_with_wallet(&commit, Some(&inputs), None)
                .await?;

            raw_txs.push(signed_raw_commit_tx.hex);

            let serialized_reveal_tx = encode::serialize(&reveal);
            raw_txs.push(serialized_reveal_tx);
        }

        let mut inputs = vec![];
        for input in commit.input.iter() {
            if let Some(entry) = all_tx_map.get(&input.previous_output.txid) {
                inputs.push(SignRawTransactionInput {
                    txid: input.previous_output.txid,
                    vout: input.previous_output.vout,
                    script_pub_key: entry.output[input.previous_output.vout as usize]
                        .script_pubkey
                        .clone(),
                    redeem_script: None,
                    amount: Some(entry.output[input.previous_output.vout as usize].value),
                });
            }
        }
        let signed_raw_commit_tx = client
            .sign_raw_transaction_with_wallet(&commit, Some(&inputs), None)
            .await?;

        raw_txs.push(signed_raw_commit_tx.hex);

        let serialized_reveal_tx = encode::serialize(&reveal.tx);
        raw_txs.push(serialized_reveal_tx);

        let mut txids = Vec::new();
        for raw_tx in raw_txs {
            let txid = client.send_raw_transaction(&raw_tx).await?;
            txids.push(txid);
        }

        Ok(txids)
    }
}

#[async_trait]
impl TestCase for UndecompressableBlobTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 171,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-fallbackfee=0.00001"],
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let prover_da_service = spawn_bitcoin_da_prover_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
            network: Network::Nightly,
        });

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Wait for batch prover tx to be sent to DA
        da.wait_mempool_len(2, None).await?;

        // Send a complete tx with dummy body
        Self::send_complete_tx(&batch_prover.da).await?;

        // Wait for batch prover tx and the test reveal tx to be in mempool
        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        let block_hash = da.get_block_hash(finalized_height).await?;
        let block = da.get_block(&block_hash).await?;

        let mut txs: Vec<_> = block
            .txdata
            .iter()
            .filter(|tx| tx.input[0].witness.len() == 3)
            .collect();

        txs.sort_by(|a, b| a.input[0].witness.size().cmp(&b.input[0].witness.size()));
        assert!(Self::verify_complete_is_non_decompressable(txs[0])); // First tx has `vec![1u8; 64]` body and should be undecompressable
        assert!(!Self::verify_complete_is_non_decompressable(txs[1])); // Second tx is correct batch prover reveal tx

        // LCP should be able to process it and tick along
        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // LCP should have processed the proof and skipped the fake complete proof
        let lcp_output = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?
            .unwrap()
            .light_client_proof_output;
        assert_eq!(lcp_output.last_sequencer_commitment_index.to::<u32>(), 1);
        assert_eq!(
            lcp_output.last_l2_height.to::<u64>(),
            max_l2_blocks_per_commitment
        );

        let block = prover_da_service
            .get_block_by_hash(block_hash.into())
            .await
            .unwrap();

        let (mut txs, inclusion_proof, completeness_proof) =
            prover_da_service.extract_relevant_blobs_with_proof(&block);

        txs.iter_mut().for_each(|t| {
            t.full_data();
        });

        assert_eq!(
            verifier.verify_transactions(&block.header, inclusion_proof, completeness_proof,),
            Ok(txs),
        );

        da.generate(1).await?;

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Wait for batch prover tx to be sent to DA
        da.wait_mempool_len(2, None).await?;

        // Send a chunked tx with dummy body
        let txids = Self::send_chunked_tx(&batch_prover.da).await?;

        // // Wait for batch prover tx and chunked txs to hit the mempool
        da.wait_mempool_len(txids.len() + 2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        let block_hash = da.get_block_hash(finalized_height).await?;
        let block = da.get_block(&block_hash).await?;

        assert!(Self::verify_chunked_is_non_decompressable(&block));

        // LCP should be able to process it and tick along
        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // LCP should have processed the proof and skipped the fake chunked proof
        let lcp_output = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?
            .unwrap()
            .light_client_proof_output;
        assert_eq!(lcp_output.last_sequencer_commitment_index.to::<u32>(), 2);
        assert_eq!(
            lcp_output.last_l2_height.to::<u64>(),
            max_l2_blocks_per_commitment * 2
        );

        let block = prover_da_service
            .get_block_by_hash(block_hash.into())
            .await
            .unwrap();

        let (mut txs, inclusion_proof, completeness_proof) =
            prover_da_service.extract_relevant_blobs_with_proof(&block);

        txs.iter_mut().for_each(|t| {
            t.full_data();
        });

        assert_eq!(
            verifier.verify_transactions(&block.header, inclusion_proof, completeness_proof,),
            Ok(txs),
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_undecompressable_blob() -> Result<()> {
    TestCaseRunner::new(UndecompressableBlobTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct ProvingSessionInfoTest;

#[async_trait]
impl TestCase for ProvingSessionInfoTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            with_sequencer: false,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        light_client_prover.wait_for_l1_height(1, None).await?;
        let proof_response = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(1))
            .await?
            .expect("proving job should exist");

        let proving_info = proof_response.info;
        let Some(ProvingSessionInfo::Local(local_info)) = proving_info else {
            panic!("unexpected proving info type");
        };

        assert!(local_info.segments > 0);
        assert!(local_info.total_cycles > 0);
        assert!(local_info.user_cycles > 0);
        assert!(local_info.paging_cycles > 0);
        assert!(local_info.reserved_cycles > 0);
        Ok(())
    }
}

#[tokio::test]
async fn proving_session_info_test() -> Result<()> {
    TestCaseRunner::new(ProvingSessionInfoTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct SecurityCouncilMemberManagementTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for SecurityCouncilMemberManagementTest {
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
            max_l2_blocks_per_commitment: 2,
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

    fn scan_l1_start_height() -> Option<u64> {
        Some(195)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Other(
                BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS[0].to_string(),
            ),
            REVEAL_TX_PREFIX.to_vec(),
            None,
            None,
        )
        .await;

        // Bootstrap: create L2 blocks, sequencer commitments, and batch proofs
        // so the light client prover starts processing L1 blocks.
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;

        // Verify initial state: 5 members, threshold 3
        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(addresses.len(), 5, "Initial council should have 5 members");

        let threshold = light_client_prover
            .client
            .http_client()
            .get_security_council_threshold()
            .await?;
        assert_eq!(threshold, 3, "Initial threshold should be 3");

        let pk_bytes_arr: [[u8; 32]; 5] = BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS
            .map(|s| hex::decode(s).unwrap().try_into().unwrap());
        let (_initial_addresses, signers) =
            generate_initial_addresses_with_signers_from_pks(&pk_bytes_arr);

        // --- CASE 0: Valid add member ---
        // Add a new member with threshold 3. After adding: 6 members, max threshold = 6-2=4, so 3 is valid.
        let new_member_1 = [0x11u8; 20];
        let add_body_1 = AddSecurityCouncilMemberV1Body {
            new_member: new_member_1,
            new_threshold: 3,
            nonce: 1,
        };
        let payload = AddSecurityCouncilMember::from(add_body_1.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::AddSecurityCouncilMemberV1(add_body_1),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses.len(),
            6,
            "CASE 1: Should have 6 members after valid add"
        );

        let threshold = light_client_prover
            .client
            .http_client()
            .get_security_council_threshold()
            .await?;
        assert_eq!(threshold, 3, "CASE 1: Threshold should be 3");

        // --- CASE 1: Invalid add member (should be rejected) ---
        // Add a new member with threshold 6. After adding: 7 members, max threshold = 7-2=5, so 6 is invalid.
        let new_member_2 = [0x14u8; 20];
        let add_body_1 = AddSecurityCouncilMemberV1Body {
            new_member: new_member_2,
            new_threshold: 6,
            nonce: 2,
        };
        let payload = AddSecurityCouncilMember::from(add_body_1.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::AddSecurityCouncilMemberV1(add_body_1),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses.len(),
            6,
            "CASE 1: Should still have 6 members after invalid add"
        );

        let threshold = light_client_prover
            .client
            .http_client()
            .get_security_council_threshold()
            .await?;
        assert_eq!(threshold, 3, "CASE 1: Threshold should still be 3");

        // --- CASE 2: Add member with threshold just okay with the new member ---
        // Member count goes up to 7, threshold goes up to 5
        // Currently 6 members + 1, max threshold = 7-2=5. Requesting threshold=5 is valid.
        let new_member_2 = [0x22u8; 20];
        let add_body_2 = AddSecurityCouncilMemberV1Body {
            new_member: new_member_2,
            new_threshold: 5,
            nonce: 3, // CASE 1 consumed nonce 2
        };
        let payload = AddSecurityCouncilMember::from(add_body_2.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::AddSecurityCouncilMemberV1(add_body_2),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let threshold = light_client_prover
            .client
            .http_client()
            .get_security_council_threshold()
            .await?;
        assert_eq!(threshold, 5, "CASE2: should have 5 threshold");

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(addresses.len(), 7, "CASE 2: Should have 7 members");

        // --- CASE 3: Update threshold below MIN_THRESHOLD=2 (rejected) ---
        let update_body_1 = UpdateSecurityCouncilThresholdV1Body {
            new_threshold: 1,
            nonce: 4,
        };
        let payload = UpdateSecurityCouncilThreshold::from(update_body_1.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 5);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateSecurityCouncilThresholdV1(update_body_1),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let threshold = light_client_prover
            .client
            .http_client()
            .get_security_council_threshold()
            .await?;
        assert_eq!(
            threshold, 5,
            "CASE 3: Threshold should still be 5 (below min rejected)"
        );

        // --- CASE 4: Update threshold exceeds proximity limit (rejected) ---
        // 7 members, max threshold = 7-2=5. Requesting threshold=6 is invalid.
        let update_body_2 = UpdateSecurityCouncilThresholdV1Body {
            new_threshold: 6,
            nonce: 5,
        };
        let payload = UpdateSecurityCouncilThreshold::from(update_body_2.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 5);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateSecurityCouncilThresholdV1(update_body_2),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let threshold = light_client_prover
            .client
            .http_client()
            .get_security_council_threshold()
            .await?;
        assert_eq!(
            threshold, 5,
            "CASE 4: Threshold should still be 5 (exceeds proximity rejected)"
        );

        // --- CASE 5: Valid update threshold ---
        // 7 members, max threshold = 7-2=5. Requesting threshold=4 is valid.
        let update_body_3 = UpdateSecurityCouncilThresholdV1Body {
            new_threshold: 4,
            nonce: 6,
        };
        let payload = UpdateSecurityCouncilThreshold::from(update_body_3.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 5);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateSecurityCouncilThresholdV1(update_body_3),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let threshold = light_client_prover
            .client
            .http_client()
            .get_security_council_threshold()
            .await?;
        assert_eq!(threshold, 4, "CASE 5: Threshold should be updated to 4");

        // --- CASE 6: Remove member with valid new threshold ---
        // Currently 7 members, threshold 4. Remove the newly added member.
        // After removal: 6 members, max threshold = 6-2=4. New threshold must be <= 4.
        let remove_body_1 = RemoveSecurityCouncilMemberV1Body {
            member_to_be_removed: new_member_1,
            new_threshold: 4,
            nonce: 7,
        };
        let payload = RemoveSecurityCouncilMember::from(remove_body_1.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 4);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::RemoveSecurityCouncilMemberV1(remove_body_1),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses.len(),
            6,
            "CASE 6: Should have 6 members after valid remove"
        );

        let threshold = light_client_prover
            .client
            .http_client()
            .get_security_council_threshold()
            .await?;
        assert_eq!(threshold, 4, "CASE 6: Threshold should be 4 after remove");

        // --- CASE 7: Remove member  ---
        // Currently 6 members. Remove one to get to 5 first (valid, 4 is the min).
        let member_to_remove = _initial_addresses[4];
        let remove_body_2 = RemoveSecurityCouncilMemberV1Body {
            member_to_be_removed: member_to_remove.0 .0,
            new_threshold: 2,
            nonce: 8,
        };
        let payload = RemoveSecurityCouncilMember::from(remove_body_2.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 4);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::RemoveSecurityCouncilMemberV1(remove_body_2),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses.len(),
            5,
            "CASE 7 setup: Should have 5 members after valid remove"
        );

        // Now remove another member (would leave 4, min=4). Should be valid.
        let member_to_remove_2 = _initial_addresses[3];
        let remove_body_3 = RemoveSecurityCouncilMemberV1Body {
            member_to_be_removed: member_to_remove_2.0 .0,
            new_threshold: 2,
            nonce: 9,
        };
        let payload = RemoveSecurityCouncilMember::from(remove_body_3.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 2);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::RemoveSecurityCouncilMemberV1(remove_body_3),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses.len(),
            4,
            "CASE 7: Should still have 4 members (below min rejected)"
        );

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;

        // Now try to remove another member (would leave 3, below MIN=4). Should be rejected.
        let member_to_remove_2 = Address::from_str(addresses[3].as_str()).unwrap();
        let remove_body_3 = RemoveSecurityCouncilMemberV1Body {
            member_to_be_removed: member_to_remove_2.0 .0,
            new_threshold: 2,
            nonce: 10,
        };
        let payload = RemoveSecurityCouncilMember::from(remove_body_3.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 2);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::RemoveSecurityCouncilMemberV1(remove_body_3),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses.len(),
            4,
            "CASE 7: Should still have 4 members (below min rejected)"
        );

        // --- CASE 8: Replace non-existent member (rejected) ---
        // Try to replace a member that doesn't exist in the council.
        let replace_body_1 = ReplaceSecurityCouncilMemberV1Body {
            to_be_replaced: [0xAAu8; 20], // not in council
            new_member: [0x33u8; 20],
            nonce: 11,
        };
        let payload = ReplaceSecurityCouncilMember::from(replace_body_1.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 2);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::ReplaceSecurityCouncilMemberV1(replace_body_1),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses.len(),
            4,
            "CASE 8: Should still have 4 members (non-existent member replace rejected)"
        );

        // --- CASE 9: Replace with already existing member (rejected) ---
        // Try to replace one member with another who is already in the council.
        let replace_body_2 = ReplaceSecurityCouncilMemberV1Body {
            to_be_replaced: _initial_addresses[0].0 .0,
            new_member: _initial_addresses[1].0 .0, // already in council
            nonce: 12,
        };
        let payload = ReplaceSecurityCouncilMember::from(replace_body_2.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 2);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::ReplaceSecurityCouncilMemberV1(replace_body_2),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses.len(),
            4,
            "CASE 9: Should still have 4 members (duplicate member replace rejected)"
        );

        // --- CASE 10: Valid replace member ---
        // Replace _initial_addresses[2] with a new address.
        let new_replacement = [0x33u8; 20];
        let replace_body_3 = ReplaceSecurityCouncilMemberV1Body {
            to_be_replaced: _initial_addresses[2].0 .0,
            new_member: new_replacement,
            nonce: 13,
        };
        let payload = ReplaceSecurityCouncilMember::from(replace_body_3.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 2);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::ReplaceSecurityCouncilMemberV1(replace_body_3),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses.len(),
            4,
            "CASE 10: Should still have 4 members after replace"
        );
        // Verify the old member is gone and new member is present
        let old_member_addr = format!("{:?}", _initial_addresses[2]);
        let new_member_addr = format!("{:?}", Address::from_slice(&new_replacement));
        assert!(
            !addresses.contains(&old_member_addr),
            "CASE 10: Old member should be removed"
        );
        assert!(
            addresses.contains(&new_member_addr),
            "CASE 10: New member should be present"
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_security_council_member_management_limits() -> Result<()> {
    TestCaseRunner::new(SecurityCouncilMemberManagementTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct DaPubKeyUpdateTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for DaPubKeyUpdateTest {
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
            max_l2_blocks_per_commitment: 2,
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

    fn scan_l1_start_height() -> Option<u64> {
        Some(195)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Other(
                BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS[0].to_string(),
            ),
            REVEAL_TX_PREFIX.to_vec(),
            None,
            None,
        )
        .await;

        // Bootstrap: create L2 blocks, sequencer commitments, and batch proofs
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;

        // Verify initial pub keys
        let initial_sequencer_pk = light_client_prover
            .client
            .http_client()
            .get_sequencer_da_pub_key()
            .await?;
        assert!(
            !initial_sequencer_pk.is_empty(),
            "Initial sequencer DA pub key should be set"
        );

        let initial_batch_prover_pk = light_client_prover
            .client
            .http_client()
            .get_batch_prover_da_pub_key()
            .await?;
        assert!(
            !initial_batch_prover_pk.is_empty(),
            "Initial batch prover DA pub key should be set"
        );

        // Get signers
        let pk_bytes_arr: [[u8; 32]; 5] = BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS
            .map(|s| hex::decode(s).unwrap().try_into().unwrap());
        let (_initial_addresses, signers) =
            generate_initial_addresses_with_signers_from_pks(&pk_bytes_arr);

        // --- CASE 1: Valid sequencer DA pub key update ---
        let new_sequencer_pub_key: [u8; 33] = {
            let mut key = [0x02u8; 33]; // Start with valid compressed key prefix
            key[1] = 0xAA;
            key[2] = 0xBB;
            key
        };
        let update_seq_body = UpdateSequencerDaPubKeyV1Body {
            new_pub_key: new_sequencer_pub_key,
            nonce: 1,
        };
        let payload = UpdateSequencerDaPubKey::from(update_seq_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateSequencerDaPubKeyV1(update_seq_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let sequencer_pk = light_client_prover
            .client
            .http_client()
            .get_sequencer_da_pub_key()
            .await?;
        assert_eq!(
            sequencer_pk,
            hex::encode(new_sequencer_pub_key),
            "CASE 1: Sequencer DA pub key should be updated"
        );

        // --- CASE 2: Valid batch prover DA pub key update ---
        let new_batch_prover_pub_key: [u8; 33] = {
            let mut key = [0x03u8; 33]; // Start with valid compressed key prefix
            key[1] = 0xCC;
            key[2] = 0xDD;
            key
        };
        let update_bp_body = UpdateBatchProverDaPubKeyV1Body {
            new_pub_key: new_batch_prover_pub_key,
            nonce: 2,
        };
        let payload = UpdateBatchProverDaPubKey::from(update_bp_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateBatchProverDaPubKeyV1(update_bp_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        let batch_prover_pk = light_client_prover
            .client
            .http_client()
            .get_batch_prover_da_pub_key()
            .await?;
        assert_eq!(
            batch_prover_pk,
            hex::encode(new_batch_prover_pub_key),
            "CASE 2: Batch prover DA pub key should be updated"
        );

        // --- CASE 3: Wrong signing domain should be rejected ---
        let another_sequencer_pub_key: [u8; 33] = {
            let mut key = [0x02u8; 33];
            key[1] = 0xFF;
            key[2] = 0xEE;
            key
        };
        let bad_domain_body = UpdateSequencerDaPubKeyV1Body {
            new_pub_key: another_sequencer_pub_key,
            nonce: 3,
        };
        let payload = UpdateSequencerDaPubKey::from(bad_domain_body.clone());
        // Sign with wrong domain (wrong chain_id) so signature verification fails
        let signatures_with_index =
            create_valid_signatures_with_wrong_domain(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateSequencerDaPubKeyV1(bad_domain_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(l1_height, Some(TEN_MINS))
            .await?;

        // Key should remain unchanged from CASE 1
        let sequencer_pk = light_client_prover
            .client
            .http_client()
            .get_sequencer_da_pub_key()
            .await?;
        assert_eq!(
            sequencer_pk,
            hex::encode(new_sequencer_pub_key),
            "CASE 3: Sequencer DA pub key should remain unchanged after wrong signing domain"
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_da_pub_key_update() -> Result<()> {
    TestCaseRunner::new(DaPubKeyUpdateTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

// Run lcp with pre-upgrade docker image
// generate pre upgrade proofs
// restart on any l1 height with upgraded binary
// generate upgraded proofs and see the upgrade is successful
struct TestLcpVersionUpgrade {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for TestLcpVersionUpgrade {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            docker: {
                TestCaseDockerConfig {
                    citrea: true, // Start in docker
                    bitcoin: true,
                }
            },
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 170,
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
        let sequencer = f.sequencer.as_mut().unwrap();
        let light_client_prover = f.light_client_prover.as_mut().unwrap();
        let da = f.bitcoin_nodes.get(0).unwrap();

        // === Pre-upgrade phase: generate proofs with old binary ===
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await.unwrap();

        light_client_prover
            .wait_for_l1_height(finalized_height, Some(TEN_MINS))
            .await?;

        // Get the pre-upgrade proof and record its state
        let pre_upgrade_proof = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?
            .expect("Pre-upgrade proof must exist");

        let old_method_id = pre_upgrade_proof
            .light_client_proof_output
            .light_client_proof_method_id;

        let pre_upgrade_l2_state_root = pre_upgrade_proof.light_client_proof_output.l2_state_root;
        let pre_upgrade_last_l2_height = pre_upgrade_proof.light_client_proof_output.last_l2_height;
        let pre_upgrade_last_seq_comm_idx = pre_upgrade_proof
            .light_client_proof_output
            .last_sequencer_commitment_index;

        // Record pre-upgrade JMT state
        let old_batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        let height_before = sequencer.client.ledger_get_head_l2_block_height().await?;

        let n_blocks = 2;
        for _ in 0..n_blocks {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer
            .wait_for_l2_height(height_before + n_blocks, None)
            .await?;

        let height_pre_restart = sequencer.client.ledger_get_head_l2_block_height().await?;

        // === Upgrade: restart with new binary ===
        light_client_prover.config.restart_policy = RestartPolicy::Spawn;
        light_client_prover.restart(None, None).await?;

        sequencer.config.restart_policy = RestartPolicy::Spawn;
        sequencer.restart(None, None).await?;

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let height_post_restart = sequencer.client.ledger_get_head_l2_block_height().await?;
        assert_eq!(height_pre_restart, height_post_restart);

        // === Post-upgrade phase: generate DA blocks for the new LCP to process ===
        sequencer.client.send_publish_batch_request().await?;
        sequencer
            .wait_for_l2_height(height_post_restart + 1, None)
            .await?;

        // Generate DA blocks to finalize new L1 blocks for LCP to scan
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let post_upgrade_finalized_height = da.get_finalized_height(None).await?;
        assert!(
            post_upgrade_finalized_height > finalized_height,
            "New finalized height must be greater than pre-upgrade height"
        );

        // Wait for the upgraded LCP to process new L1 blocks
        light_client_prover
            .wait_for_l1_height(post_upgrade_finalized_height, Some(TEN_MINS))
            .await?;

        // === Verify upgrade: check the post-upgrade proof ===
        let post_upgrade_proof = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(post_upgrade_finalized_height))
            .await?
            .expect("Post-upgrade proof must exist");

        let new_method_id = post_upgrade_proof
            .light_client_proof_output
            .light_client_proof_method_id;

        // 1. Method ID must have changed (new binary = new circuit ELF = new method ID)
        assert_ne!(
            old_method_id, new_method_id,
            "LCP method ID must change after upgrade"
        );

        // 2. L2 state must carry over from the pre-upgrade proof
        assert_eq!(
            post_upgrade_proof.light_client_proof_output.l2_state_root, pre_upgrade_l2_state_root,
            "L2 state root must carry over after upgrade"
        );
        assert_eq!(
            post_upgrade_proof.light_client_proof_output.last_l2_height, pre_upgrade_last_l2_height,
            "Last L2 height must carry over after upgrade"
        );
        assert_eq!(
            post_upgrade_proof
                .light_client_proof_output
                .last_sequencer_commitment_index,
            pre_upgrade_last_seq_comm_idx,
            "Last sequencer commitment index must carry over after upgrade"
        );

        // === Verify upgrade: check JMT state was re-initialized ===
        let new_batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        let new_batch_prover_da_pub_key = light_client_prover
            .client
            .http_client()
            .get_batch_prover_da_pub_key()
            .await?;
        let new_sequencer_da_pub_key = light_client_prover
            .client
            .http_client()
            .get_sequencer_da_pub_key()
            .await?;
        let new_security_council_addresses = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        let new_security_council_threshold = light_client_prover
            .client
            .http_client()
            .get_security_council_threshold()
            .await?;

        // 3. Batch proof method IDs must be re-initialized
        //    (old binary had different batch proof ELF, so method IDs differ)
        assert!(
            !new_batch_proof_method_ids.is_empty(),
            "Batch proof method IDs must not be empty after upgrade"
        );
        assert_ne!(
            old_batch_proof_method_ids, new_batch_proof_method_ids,
            "Batch proof method IDs must be re-initialized after upgrade"
        );

        // 4. Security council state must be re-initialized with current binary's values
        assert!(
            !new_security_council_addresses.is_empty(),
            "Security council addresses must not be empty after upgrade"
        );
        assert!(
            new_security_council_threshold > 0,
            "Security council threshold must be positive after upgrade"
        );

        // 5. DA pub keys must be re-initialized with current binary's values
        assert!(
            !new_batch_prover_da_pub_key.is_empty(),
            "Batch prover DA pub key must not be empty after upgrade"
        );
        assert!(
            !new_sequencer_da_pub_key.is_empty(),
            "Sequencer DA pub key must not be empty after upgrade"
        );

        // === Post-upgrade: verify security council messages work ===
        let bitcoin_da_service = spawn_bitcoin_da_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Other(
                BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS[0].to_string(),
            ),
            REVEAL_TX_PREFIX.to_vec(),
            None,
            None,
        )
        .await;

        let pk_bytes_arr: [[u8; 32]; 5] = BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS
            .map(|s| hex::decode(s).unwrap().try_into().unwrap());
        let (_initial_addresses, signers) =
            generate_initial_addresses_with_signers_from_pks(&pk_bytes_arr);

        // --- SC Message 1: Update sequencer DA pub key ---
        let updated_seq_pub_key: [u8; 33] = {
            let mut key = [0x02u8; 33];
            key[1] = 0xAA;
            key
        };
        let update_seq_body = UpdateSequencerDaPubKeyV1Body {
            new_pub_key: updated_seq_pub_key,
            nonce: 1,
        };
        let payload = UpdateSequencerDaPubKey::from(update_seq_body.clone());
        let sigs = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateSequencerDaPubKeyV1(update_seq_body),
                    signatures_with_index: sigs,
                }),
                1.0,
            )
            .await?;

        // --- SC Message 2: Update batch prover DA pub key ---
        let updated_bp_pub_key: [u8; 33] = {
            let mut key = [0x03u8; 33];
            key[1] = 0xCC;
            key
        };
        let update_bp_body = UpdateBatchProverDaPubKeyV1Body {
            new_pub_key: updated_bp_pub_key,
            nonce: 2,
        };
        let payload = UpdateBatchProverDaPubKey::from(update_bp_body.clone());
        let sigs = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateBatchProverDaPubKeyV1(update_bp_body),
                    signatures_with_index: sigs,
                }),
                1.0,
            )
            .await?;

        // --- SC Message 3: Batch proof method ID update ---
        let new_method_id_body = BatchProofMethodIdBody {
            method_id: [42u32; 8],
            activation_l2_height: 9999,
            nonce: 3,
        };
        let payload = BatchProofMethodIdUpdate::from(new_method_id_body.clone());
        let sigs = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(new_method_id_body),
                    signatures_with_index: sigs,
                }),
                1.0,
            )
            .await?;

        // Mine and wait for LCP to process block with messages 1-3
        da.wait_mempool_len(6, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let sc_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(sc_l1_height, Some(TEN_MINS))
            .await?;

        // Verify messages 1-3
        let seq_pk = light_client_prover
            .client
            .http_client()
            .get_sequencer_da_pub_key()
            .await?;
        assert_eq!(
            seq_pk,
            hex::encode(updated_seq_pub_key),
            "Sequencer DA pub key should be updated by SC message"
        );

        let bp_pk = light_client_prover
            .client
            .http_client()
            .get_batch_prover_da_pub_key()
            .await?;
        assert_eq!(
            bp_pk,
            hex::encode(updated_bp_pub_key),
            "Batch prover DA pub key should be updated by SC message"
        );

        let method_ids_after_sc = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(
            method_ids_after_sc.len() > new_batch_proof_method_ids.len(),
            "Batch proof method IDs should have a new entry after SC message"
        );

        // --- SC Message 4: Add security council member ---
        let new_member = [0x99u8; 20];
        let add_body = AddSecurityCouncilMemberV1Body {
            new_member,
            new_threshold: 3,
            nonce: 4,
        };
        let payload = AddSecurityCouncilMember::from(add_body.clone());
        let sigs = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::AddSecurityCouncilMemberV1(add_body),
                    signatures_with_index: sigs,
                }),
                1.0,
            )
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let sc_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(sc_l1_height, Some(TEN_MINS))
            .await?;

        let addresses_after_add = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses_after_add.len(),
            new_security_council_addresses.len() + 1,
            "Security council should have one more member after Add"
        );

        // --- SC Message 5: Remove security council member ---
        let remove_body = RemoveSecurityCouncilMemberV1Body {
            member_to_be_removed: new_member,
            new_threshold: 3,
            nonce: 5,
        };
        let payload = RemoveSecurityCouncilMember::from(remove_body.clone());
        let sigs = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::RemoveSecurityCouncilMemberV1(remove_body),
                    signatures_with_index: sigs,
                }),
                1.0,
            )
            .await?;

        // --- SC Message 6: Update security council threshold ---
        let threshold_body = UpdateSecurityCouncilThresholdV1Body {
            new_threshold: 2,
            nonce: 6,
        };
        let payload = UpdateSecurityCouncilThreshold::from(threshold_body.clone());
        let sigs = create_valid_signatures(&signers, &payload, 3);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateSecurityCouncilThresholdV1(
                        threshold_body,
                    ),
                    signatures_with_index: sigs,
                }),
                1.0,
            )
            .await?;

        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let sc_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(sc_l1_height, Some(TEN_MINS))
            .await?;

        let addresses_after_remove = light_client_prover
            .client
            .http_client()
            .get_security_council_addresses()
            .await?;
        assert_eq!(
            addresses_after_remove.len(),
            new_security_council_addresses.len(),
            "Security council should be back to original size after Remove"
        );

        let threshold_after = light_client_prover
            .client
            .http_client()
            .get_security_council_threshold()
            .await?;
        assert_eq!(
            threshold_after, 2,
            "Security council threshold should be updated to 2"
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_lcp_version_upgrade() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        // Image tag with the old lcp binary
        "chainwayxyz/citrea-test:f3da96cea8d59f9b72df0f1b6b80144ad47901b9",
    );
    TestCaseRunner::new(TestLcpVersionUpgrade {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct SetLcpToPreviousStateTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for SetLcpToPreviousStateTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            mode: CitreaMode::Dev,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 2,
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

    fn scan_l1_start_height() -> Option<u64> {
        Some(195)
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        // DA service for security council messages (any key works)
        let sc_da_service = spawn_bitcoin_da_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Other(
                BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS[0].to_string(),
            ),
            REVEAL_TX_PREFIX.to_vec(),
            None,
            None,
        )
        .await;

        // DA services for sending fake commitments/proofs with correct DA keys
        let sequencer_da_service = spawn_bitcoin_da_sequencer_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;
        let prover_da_service = spawn_bitcoin_da_prover_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        // Get signers for security council messages
        let pk_bytes_arr: [[u8; 32]; 5] = BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS
            .map(|s| hex::decode(s).unwrap().try_into().unwrap());
        let (_initial_addresses, signers) =
            generate_initial_addresses_with_signers_from_pks(&pk_bytes_arr);

        // ========================================================
        // PHASE 1: Normal operation - commitments 1-2, batch proof, LCP processes
        // ========================================================
        for _ in 0..(2 * max_l2_blocks_per_commitment) {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(2 * max_l2_blocks_per_commitment, None)
            .await?;
        da.wait_mempool_len(4, None).await?; // 2 commitments * 2 txs each
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await?;
        da.wait_mempool_len(2, None).await?; // batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height_1 = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height_1, Some(TEN_MINS))
            .await?;

        // Verify LCP processed the batch proof
        let lcp_1 = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height_1))
            .await?
            .expect("LCP proof must exist after phase 1");

        let _phase1_state_root = lcp_1.light_client_proof_output.l2_state_root;
        let _phase1_last_l2_height = lcp_1.light_client_proof_output.last_l2_height;
        let phase1_last_seq_comm_idx = lcp_1
            .light_client_proof_output
            .last_sequencer_commitment_index;

        assert!(
            phase1_last_seq_comm_idx.to::<u32>() >= 1,
            "Phase 1: LCP should have processed at least 1 commitment"
        );

        // ========================================================
        // PHASE 2: More commitments 3-4, batch proof, LCP processes
        // ========================================================
        let l2_height = sequencer.client.ledger_get_head_l2_block_height().await?;
        for _ in 0..(2 * max_l2_blocks_per_commitment) {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(l2_height + 2 * max_l2_blocks_per_commitment, None)
            .await?;
        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height_2 = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height_2, Some(TEN_MINS))
            .await?;

        let lcp_2 = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height_2))
            .await?
            .expect("LCP proof must exist after phase 2");

        let phase2_state_root = lcp_2.light_client_proof_output.l2_state_root;
        let phase2_last_l2_height = lcp_2.light_client_proof_output.last_l2_height;
        let phase2_last_seq_comm_idx = lcp_2
            .light_client_proof_output
            .last_sequencer_commitment_index;

        assert!(
            phase2_last_seq_comm_idx > phase1_last_seq_comm_idx,
            "Phase 2: LCP should have advanced beyond phase 1"
        );

        // ========================================================
        // PHASE 3: SC sends BatchProofMethodIdUpdate (new method ID)
        // ========================================================
        let new_method_id = [42u32; 8];
        let method_id_body = BatchProofMethodIdBody {
            method_id: new_method_id,
            activation_l2_height: 9,
            nonce: 1,
        };
        let payload = BatchProofMethodIdUpdate::from(method_id_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        sc_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::BatchProofMethodIdUpdateV1(method_id_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let method_id_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(method_id_l1_height, Some(TEN_MINS))
            .await?;

        // Verify method ID was added
        let method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(
            method_ids.len() >= 2,
            "Phase 3: Should have at least 2 method IDs after update"
        );

        // ========================================================
        // PHASE 4: Send fake commitments + fake batch proof with new method ID
        // ========================================================
        let next_comm_idx = phase2_last_seq_comm_idx.to::<u32>() + 1;

        // Create fake sequencer commitments continuing from where phase 2 left off
        let fake_commitment_1 = SequencerCommitment {
            merkle_root: [0xA1u8; 32],
            index: next_comm_idx,
            l2_end_block_number: phase2_last_l2_height.to::<u64>() + 100,
        };
        let fake_commitment_2 = SequencerCommitment {
            merkle_root: [0xA2u8; 32],
            index: next_comm_idx + 1,
            l2_end_block_number: phase2_last_l2_height.to::<u64>() + 200,
        };

        // Send fake sequencer commitments via sequencer DA service (correct DA key)
        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_commitment_1.clone()),
                1.0,
            )
            .await?;
        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_commitment_2.clone()),
                1.0,
            )
            .await?;

        // Wait for full node to have processed phase 2 commitments so we can get the
        // previous commitment hash for chaining
        full_node
            .wait_for_l1_height(batch_proof_l1_height_2, Some(TEN_MINS))
            .await?;
        let prev_commitment = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(phase2_last_seq_comm_idx.to::<u32>()))
            .await?
            .expect("Previous commitment must exist");
        let prev_commitment_as_seq = SequencerCommitment {
            merkle_root: prev_commitment.merkle_root,
            index: prev_commitment.index.to::<u32>(),
            l2_end_block_number: prev_commitment.l2_end_block_number.to::<u64>(),
        };

        // 2 commitments (4 txs)
        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Get an L1 block hash for the fake batch proof
        let l1_hash = da
            .get_block_hash(da.get_finalized_height(None).await?)
            .await?;

        // Create fake batch proof covering both fake commitments with the new method ID
        let fake_batch_proof = create_serialized_fake_receipt_batch_proof(
            phase2_state_root,
            fake_commitment_2.l2_end_block_number,
            new_method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_commitment_1.clone(), fake_commitment_2.clone()],
            Some(prev_commitment_as_seq.serialize_and_calculate_sha_256()),
        );

        // Send fake batch proof via batch prover DA service (correct DA key)
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(fake_batch_proof), 1.0)
            .await?;

        // 1 batch proof (2 txs)
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let fake_proof_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(fake_proof_l1_height, Some(TEN_MINS))
            .await?;

        // Verify LCP advanced with the fake batch proof
        let lcp_after_fake = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(fake_proof_l1_height))
            .await?
            .expect("LCP proof must exist after fake batch proof");

        assert!(
            lcp_after_fake
                .light_client_proof_output
                .last_sequencer_commitment_index
                .to::<u32>()
                > phase2_last_seq_comm_idx.to::<u32>(),
            "Phase 4: LCP should have advanced with fake batch proof"
        );

        // ========================================================
        // PHASE 5: SC removes the new method ID
        // ========================================================
        // Find the index of the new method ID in the list
        let method_id_index = method_ids
            .iter()
            .position(|m| m.method_id == new_method_id.into())
            .expect("New method ID must be in the list") as u32;

        let remove_body = RemoveBatchProofMethodIdV1Body {
            method_id_index,
            batch_proof_method_id: new_method_id,
            l2_activation_height: 9,
            nonce: 2,
        };
        let payload = RemoveBatchProofMethodId::from(remove_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        sc_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::RemoveBatchProofMethodIdV1(remove_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let remove_method_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(remove_method_l1_height, Some(TEN_MINS))
            .await?;

        // Verify method ID was removed
        let method_ids_after_remove = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert!(
            !method_ids_after_remove
                .iter()
                .any(|m| m.method_id == new_method_id.into()),
            "Phase 5: New method ID should be removed"
        );

        // ========================================================
        // PHASE 6: SC sends SetLcpToPreviousState to revert to phase 2 end
        // ========================================================
        let revert_target_idx = phase2_last_seq_comm_idx.to::<u32>();

        // Get sequencer commitment data at the revert target index
        let target_commitment = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(revert_target_idx))
            .await?
            .expect("Sequencer commitment must exist at revert target index");

        let set_lcp_body = SetLcpToPreviousStateV1Body {
            pre_state_root: phase2_state_root,
            index: revert_target_idx,
            last_l2_height: target_commitment.l2_end_block_number.to::<u64>(),
            merkle_root: target_commitment.merkle_root,
            nonce: 3,
        };
        let payload = SetLcpToPreviousState::from(set_lcp_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        sc_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::SetLcpToPreviousStateV1(set_lcp_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let revert_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(revert_l1_height, Some(TEN_MINS))
            .await?;

        // Verify LCP state was reverted to phase 2
        let lcp_after_revert = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(revert_l1_height))
            .await?
            .expect("LCP proof must exist after revert");

        assert_eq!(
            lcp_after_revert
                .light_client_proof_output
                .last_sequencer_commitment_index
                .to::<u32>(),
            revert_target_idx,
            "Phase 6: LCP last_sequencer_commitment_index should be reverted"
        );
        assert_eq!(
            lcp_after_revert.light_client_proof_output.l2_state_root, phase2_state_root,
            "Phase 6: LCP l2_state_root should be reverted to phase 2 state"
        );
        assert_eq!(
            lcp_after_revert.light_client_proof_output.last_l2_height, phase2_last_l2_height,
            "Phase 6: LCP last_l2_height should be reverted to phase 2 height"
        );

        // ========================================================
        // PHASE 7: SC updates sequencer and batch prover DA pub keys
        // ========================================================
        // Use real key pairs so we can create DA services with the new private keys later
        let new_seq_private_key =
            "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2";
        let new_bp_private_key = "B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3";

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let new_seq_secret_key = bitcoin::secp256k1::SecretKey::from_str(new_seq_private_key)?;
        let new_seq_pub_key =
            bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &new_seq_secret_key);
        let new_sequencer_pub_key: [u8; 33] = new_seq_pub_key.serialize();

        let new_bp_secret_key = bitcoin::secp256k1::SecretKey::from_str(new_bp_private_key)?;
        let new_bp_pub_key =
            bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &new_bp_secret_key);
        let new_batch_prover_pub_key: [u8; 33] = new_bp_pub_key.serialize();

        let update_seq_body = UpdateSequencerDaPubKeyV1Body {
            new_pub_key: new_sequencer_pub_key,
            nonce: 4,
        };
        let payload = UpdateSequencerDaPubKey::from(update_seq_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        sc_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateSequencerDaPubKeyV1(update_seq_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;

        let update_bp_body = UpdateBatchProverDaPubKeyV1Body {
            new_pub_key: new_batch_prover_pub_key,
            nonce: 5,
        };
        let payload = UpdateBatchProverDaPubKey::from(update_bp_body.clone());
        let signatures_with_index = create_valid_signatures(&signers, &payload, 3);
        sc_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SecurityCouncilTx(SecurityCouncilTx {
                    tx_type: SecurityCouncilTxType::UpdateBatchProverDaPubKeyV1(update_bp_body),
                    signatures_with_index,
                }),
                1.0,
            )
            .await?;

        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let pubkey_update_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(pubkey_update_l1_height, Some(TEN_MINS))
            .await?;

        // Verify pub keys were updated
        let sequencer_pk = light_client_prover
            .client
            .http_client()
            .get_sequencer_da_pub_key()
            .await?;
        assert_eq!(
            sequencer_pk,
            hex::encode(new_sequencer_pub_key),
            "Phase 7: Sequencer DA pub key should be updated"
        );

        let batch_prover_pk = light_client_prover
            .client
            .http_client()
            .get_batch_prover_da_pub_key()
            .await?;
        assert_eq!(
            batch_prover_pk,
            hex::encode(new_batch_prover_pub_key),
            "Phase 7: Batch prover DA pub key should be updated"
        );

        // ========================================================
        // PHASE 8: Hacked key sends commitments+proofs → LCP ignores them
        // ========================================================
        // The sequencer and batch prover are still running with the old (hacked) keys.
        // They will produce new commitments and proofs, but LCP should reject them
        // because the DA pub keys have been updated.
        let fake_commitment = SequencerCommitment {
            merkle_root: [0xDEu8; 32],
            index: revert_target_idx + 1,
            l2_end_block_number: phase2_last_l2_height.to::<u64>() + 300,
        };

        // Send fake commitment and batch proof with old keys
        sequencer_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_commitment.clone()),
                1.0,
            )
            .await?;

        // 1 commitment (2 txs)
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let l1_block_hash = da
            .get_block_hash(da.get_finalized_height(None).await?)
            .await?;
        let fake_batch_proof = create_serialized_fake_receipt_batch_proof(
            phase2_state_root,
            fake_commitment.l2_end_block_number,
            new_method_id,
            None,
            false,
            l1_block_hash.as_raw_hash().to_byte_array(),
            vec![fake_commitment.clone()],
            Some(prev_commitment_as_seq.serialize_and_calculate_sha_256()),
        );
        prover_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(fake_batch_proof), 1.0)
            .await?;

        // 1 batch proof (2 txs)
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let hacked_batch_proof_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(hacked_batch_proof_l1_height, Some(TEN_MINS))
            .await?;

        // Verify LCP did NOT advance - it should still be at the reverted state
        let lcp_after_hacked = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(hacked_batch_proof_l1_height))
            .await?
            .expect("LCP proof must exist");

        assert_eq!(
            lcp_after_hacked
                .light_client_proof_output
                .last_sequencer_commitment_index
                .to::<u32>(),
            revert_target_idx,
            "Phase 8: LCP should not advance with hacked key commitments/proofs"
        );
        assert_eq!(
            lcp_after_hacked.light_client_proof_output.l2_state_root, phase2_state_root,
            "Phase 8: LCP state root should remain at reverted state"
        );

        // ========================================================
        // PHASE 9: New key sends fake commitments+proofs → LCP accepts them
        // ========================================================
        // Create DA services with the new private keys (matching the updated pub keys)
        let new_seq_da_service = spawn_bitcoin_da_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Other(new_seq_private_key.to_string()),
            REVEAL_TX_PREFIX.to_vec(),
            None,
            None,
        )
        .await;

        let new_bp_da_service = spawn_bitcoin_da_service(
            &self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Other(new_bp_private_key.to_string()),
            REVEAL_TX_PREFIX.to_vec(),
            None,
            None,
        )
        .await;

        // Get the current batch proof method IDs (the original one should still be valid)
        let current_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        let valid_method_id: [u32; 8] = current_method_ids[0].method_id.into();

        // Get an L1 block hash for the fake batch proof
        let l1_hash = da.get_block_hash(hacked_batch_proof_l1_height).await?;

        // Create fake sequencer commitments continuing from the reverted state
        let new_comm_idx = revert_target_idx + 1;
        let new_fake_commitment = SequencerCommitment {
            merkle_root: [0xB1u8; 32],
            index: new_comm_idx,
            l2_end_block_number: phase2_last_l2_height.to::<u64>() + 100,
        };

        // Get the previous commitment hash for chaining
        let prev_commitment_for_phase9 = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(revert_target_idx))
            .await?
            .expect("Previous commitment must exist for phase 9");
        let prev_commitment_as_seq_9 = SequencerCommitment {
            merkle_root: prev_commitment_for_phase9.merkle_root,
            index: prev_commitment_for_phase9.index.to::<u32>(),
            l2_end_block_number: prev_commitment_for_phase9.l2_end_block_number.to::<u64>(),
        };

        // Send fake commitment via new sequencer DA service (new key)
        new_seq_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(new_fake_commitment.clone()),
                1.0,
            )
            .await?;

        // Create and send fake batch proof with the original method ID via new prover DA service
        let new_fake_batch_proof = create_serialized_fake_receipt_batch_proof(
            phase2_state_root,
            new_fake_commitment.l2_end_block_number,
            valid_method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![new_fake_commitment.clone()],
            Some(prev_commitment_as_seq_9.serialize_and_calculate_sha_256()),
        );

        new_bp_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(new_fake_batch_proof), 1.0)
            .await?;

        // 1 commitment (2 txs) + 1 batch proof (2 txs) = 4 txs
        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let new_key_l1_height = da.get_finalized_height(None).await?;
        light_client_prover
            .wait_for_l1_height(new_key_l1_height, Some(TEN_MINS))
            .await?;

        // Verify LCP advanced with the new key's commitments/proofs
        let lcp_after_new_key = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(new_key_l1_height))
            .await?
            .expect("LCP proof must exist after new key proofs");

        assert_eq!(
            lcp_after_new_key
                .light_client_proof_output
                .last_sequencer_commitment_index
                .to::<u32>(),
            new_comm_idx,
            "Phase 9: LCP should advance with new key commitments/proofs"
        );
        assert_ne!(
            lcp_after_new_key.light_client_proof_output.l2_state_root, phase2_state_root,
            "Phase 9: LCP state root should have changed"
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_set_lcp_to_previous_state() -> Result<()> {
    TestCaseRunner::new(SetLcpToPreviousStateTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}
