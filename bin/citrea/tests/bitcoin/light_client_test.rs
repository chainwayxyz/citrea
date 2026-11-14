use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{eip191_hash_message, U32, U64};
use async_trait::async_trait;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, sha256d, Hash, HashEngine};
use bitcoin::opcodes::all::OP_2DROP;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::script::Builder as ScriptBuilder;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_da::helpers::parsers::{parse_relevant_transaction, ParsedTransaction, VerifyParsed};
use bitcoin_da::spec::{BitcoinSpec, RollupParams};
use bitcoin_da::utxo_manager::UtxoContext;
use bitcoin_da::verifier::BitcoinVerifier;
use bitcoincore_rpc::{Client, RpcApi};
use borsh::BorshDeserialize;
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_batch_prover::PartitionMode;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{
    BatchProverConfig, BitcoinConfig, CitreaMode, LightClientProverConfig, SequencerConfig,
    SequencerMempoolConfig, TestCaseConfig,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_fullnode::rpc::FullNodeRpcClient;
use citrea_light_client_prover::circuit::citrea_network_to_chain_id;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use citrea_primitives::compression::{compress_blob, decompress_blob};
use citrea_primitives::REVEAL_TX_PREFIX;
use rand::{thread_rng, Rng};
use reth_tasks::TaskManager;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{
    BatchProofMethodId, BatchProofMethodIdBody, BlockHeaderTrait, DaTxRequest, DaVerifier,
    DataOnDa, SequencerCommitment,
};
use sov_rollup_interface::rpc::BatchProofMethodIdRpcResponse;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::batch_proof::output::{BatchProofCircuitOutput, CumulativeStateDiff};
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::sp1::SP1Proof;
use sov_rollup_interface::zk::ProvingSessionInfo;
use sov_rollup_interface::Network;

use super::get_citrea_path;
use super::utils::PROVER_DA_PRIVATE_KEY;
use crate::bitcoin::utils::{
    create_valid_signatures, generate_initial_pub_keys_with_signers_from_pks,
    spawn_bitcoin_da_prover_service, spawn_bitcoin_da_sequencer_service, spawn_bitcoin_da_service,
    wait_for_prover_job, wait_for_zkproofs, DaServiceKeyKind,
    BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS,
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
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
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
            proof_sampling_number: 99999999,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
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
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
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
                method_id: citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ID
            }],
        );

        // Send BatchProofMethodId transaction to da
        let new_batch_proof_method_id = [1u32; 8];
        let method_id_body = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id,
            activation_l2_height: 210,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };

        let pk_bytes_arr: [[u8; 32]; 5] = BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS
            .map(|s| hex::decode(s).unwrap().try_into().unwrap());

        let (_initial_pubkeys, signers) =
            generate_initial_pub_keys_with_signers_from_pks(pk_bytes_arr);

        let msg = method_id_body.serialize();
        let prehash = eip191_hash_message(msg.as_slice());

        let signatures_with_index = create_valid_signatures(&signers, &prehash);

        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::BatchProofMethodId(BatchProofMethodId {
                    body: method_id_body,
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
                    method_id: citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ID
                },
                BatchProofMethodIdRpcResponse {
                    height: U64::from(210),
                    method_id: new_batch_proof_method_id
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
                    method_id: citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ID
                },
                BatchProofMethodIdRpcResponse {
                    height: U64::from(210),
                    method_id: new_batch_proof_method_id
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
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
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
                method_id: citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ID
            }]
        );

        // --- CASE 1: All valid signatures and pubkeys ---
        let new_batch_proof_method_id = [2u32; 8];
        let method_id_body = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id,
            activation_l2_height: 220,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };
        let pk_bytes_arr: [[u8; 32]; 5] = BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS
            .map(|s| hex::decode(s).unwrap().try_into().unwrap());

        let (_initial_pubkeys, signers) =
            generate_initial_pub_keys_with_signers_from_pks(pk_bytes_arr);

        let msg = method_id_body.serialize();
        let prehash = eip191_hash_message(msg.as_slice());

        let signatures_with_index = create_valid_signatures(&signers, &prehash);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::BatchProofMethodId(BatchProofMethodId {
                    body: method_id_body.clone(),
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
            .any(|x| x.method_id == new_batch_proof_method_id));

        // --- CASE 2: Invalid signature (should be rejected) ---
        let new_batch_proof_method_id2 = [3u32; 8];
        let method_id_body2 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id2,
            activation_l2_height: 230,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };
        let msg2 = method_id_body2.serialize();
        let prehash2 = eip191_hash_message(msg2.as_slice());

        let mut signatures_with_index = create_valid_signatures(&signers, &prehash2);

        // Corrupt one signature
        signatures_with_index[0].0[0] ^= 0xFF;

        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::BatchProofMethodId(BatchProofMethodId {
                    body: method_id_body2.clone(),
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
            .any(|x| x.method_id == new_batch_proof_method_id2));

        // --- CASE 3: Test signature with duplicate pubkey index (should be rejected) ---
        let new_batch_proof_method_id3 = [4u32; 8];
        let method_id_body3 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id3,
            activation_l2_height: 240,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };
        let msg3 = method_id_body3.serialize();
        let prehash3 = eip191_hash_message(msg3.as_slice());

        let mut signatures_with_index = create_valid_signatures(&signers, &prehash3);

        // Corrupt one signature
        signatures_with_index[0].1 = signatures_with_index[2].1;
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::BatchProofMethodId(BatchProofMethodId {
                    body: method_id_body3.clone(),
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
            .any(|x| x.method_id == new_batch_proof_method_id3));

        // --- CASE 4: Test signature with pubkey index out of bounds (should be rejected) ---
        let new_batch_proof_method_id3 = [4u32; 8];
        let method_id_body3 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id3,
            activation_l2_height: 240,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };
        let msg3 = method_id_body3.serialize();
        let prehash3 = eip191_hash_message(msg3.as_slice());

        let mut signatures_with_index = create_valid_signatures(&signers, &prehash3);

        // Corrupt one signature
        signatures_with_index[2].1 = 5; // out of bounds
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::BatchProofMethodId(BatchProofMethodId {
                    body: method_id_body3.clone(),
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
            .any(|x| x.method_id == new_batch_proof_method_id3));

        // --- CASE 4: Test signature with pubkey index Swapped (should be rejected) ---
        let new_batch_proof_method_id3 = [4u32; 8];
        let method_id_body3 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id3,
            activation_l2_height: 240,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };
        let msg3 = method_id_body3.serialize();
        let prehash3 = eip191_hash_message(msg3.as_slice());

        let mut signatures_with_index = create_valid_signatures(&signers, &prehash3);

        // Swap pubkey indices of the first and last signature
        // This should be rejected as now signatures will point to wrong pubkeys
        let tmp = signatures_with_index[0].1;
        signatures_with_index[0].1 = signatures_with_index[2].1;
        signatures_with_index[2].1 = tmp;

        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::BatchProofMethodId(BatchProofMethodId {
                    body: method_id_body3.clone(),
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
            .any(|x| x.method_id == new_batch_proof_method_id3));

        // Case 5: Test with wrong network (should be rejected)
        let new_batch_proof_method_id4 = [5u32; 8];
        let method_id_body4 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id4,
            activation_l2_height: 250,
            chain_id: citrea_network_to_chain_id(Network::Mainnet),
        };
        let msg4 = method_id_body4.serialize();
        let prehash4 = eip191_hash_message(msg4.as_slice());
        let signatures_with_index = create_valid_signatures(&signers, &prehash4);
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::BatchProofMethodId(BatchProofMethodId {
                    body: method_id_body4.clone(),
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
            .any(|x| x.method_id == new_batch_proof_method_id4));

        // Case 6: Test signature indexes not ascending order (should be rejected)
        let new_batch_proof_method_id5 = [6u32; 8];
        let method_id_body5 = BatchProofMethodIdBody {
            method_id: new_batch_proof_method_id5,
            activation_l2_height: 260,

            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };
        let msg5 = method_id_body5.serialize();
        let prehash5 = eip191_hash_message(msg5.as_slice());
        let mut signatures_with_index = create_valid_signatures(&signers, &prehash5);
        // Make indexes not in ascending order
        signatures_with_index.swap(0, 2);

        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::BatchProofMethodId(BatchProofMethodId {
                    body: method_id_body5.clone(),
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
            .any(|x| x.method_id == new_batch_proof_method_id5));

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
            batch_proof_method_ids[0].method_id,
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
            batch_proof_method_ids[0].method_id,
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
            batch_proof_method_ids[0].method_id,
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
            batch_proof_method_ids[0].method_id,
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
            batch_proof_method_ids[0].method_id,
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
            batch_proof_method_ids[0].method_id,
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

        let method_id = batch_proof_method_ids[0].method_id;
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

        let method_id = batch_proof_method_ids[0].method_id;
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
            method_ids[0].method_id,
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
            method_ids[0].method_id,
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
            method_ids[0].method_id,
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

        let method_id = batch_proof_method_ids[0].method_id;
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
            batch_proof_method_ids[0].method_id,
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
            batch_proof_method_ids[0].method_id,
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
            batch_proof_method_ids[0].method_id,
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

    borsh::to_vec(&SP1Proof::Mock {
        program: method_id,
        public_values: output_serialized,
    })
    .unwrap()
}

const POISONED_COMPLETE_BODY: [u8; 5] = [DataOnDa::COMPLETE_TAG, 0xff, 0xff, 0xff, 0x7f];

struct PoisonedDataOnDaBodyTest {
    task_manager: TaskManager,
}

impl PoisonedDataOnDaBodyTest {
    /// Inscribes a `DataOnDa::Complete` header that declares a ~2 GiB body while carrying an empty one.
    async fn send_poisoned_complete_tx(client: &Client) -> anyhow::Result<[u8; 32]> {
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

        let DaTxs::Complete { commit, reveal } = create_inscription_type_0(
            POISONED_COMPLETE_BODY.to_vec(),
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
        client
            .send_raw_transaction(&signed_raw_commit_tx.hex)
            .await?;
        client
            .send_raw_transaction(&bitcoin::consensus::encode::serialize(&reveal.tx))
            .await?;

        Ok(reveal.tx.compute_wtxid().to_byte_array())
    }
}

#[async_trait]
impl TestCase for PoisonedDataOnDaBodyTest {
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

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;

        // Send the poisoned tx so that it is mined into the same block as the honest batch proof
        let poisoned_wtxid = Self::send_poisoned_complete_tx(&batch_prover.da).await?;

        // Wait for batch prover tx and the poisoned commit/reveal pair to be in mempool
        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;
        let block_hash = da.get_block_hash(finalized_height).await?;
        let block = prover_da_service
            .get_block_by_hash(block_hash.into())
            .await
            .unwrap();

        let (txs, inclusion_proof, completeness_proof) =
            prover_da_service.extract_relevant_blobs_with_proof(&block);

        assert!(
            completeness_proof
                .iter()
                .any(|tx| tx.wtxid() == poisoned_wtxid),
            "poisoned tx must be mined and relevant"
        );

        // The native circuit run parses every extracted blob, so the poisoned one must
        // not reach it either
        assert!(
            !txs.iter().any(|blob| blob.wtxid() == poisoned_wtxid),
            "poisoned blob must be dropped by extract_relevant_blobs_with_proof"
        );
        assert!(!txs.is_empty(), "honest batch proof must be extracted");

        let verified_txs = verifier
            .verify_transactions(&block.header, inclusion_proof, completeness_proof)
            .unwrap();
        assert!(
            !verified_txs
                .iter()
                .any(|blob| blob.wtxid() == poisoned_wtxid),
            "poisoned blob must be dropped by verify_transactions"
        );

        // Native extraction and the verifier agree on the blobs of the block
        assert_eq!(verified_txs, txs);

        // LCP should be able to process the block with the poisoned blob filtered out
        light_client_prover
            .wait_for_l1_height(finalized_height, Some(TEN_MINS))
            .await?;

        // LCP should have processed the honest batch proof
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

        Ok(())
    }
}

#[tokio::test]
async fn test_poisoned_data_on_da_body_is_filtered() -> Result<()> {
    TestCaseRunner::new(PoisonedDataOnDaBodyTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
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
            .chain([&commit, &reveal.tx])
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

struct LightClientCreateCircuitInputRpcTest;

#[async_trait]
impl TestCase for LightClientCreateCircuitInputRpcTest {
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
            max_l2_blocks_per_commitment: 5,
            da_update_interval_ms: 500,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            proof_sampling_number: 99999999,
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

        let job_ids = batch_prover
            .client
            .http_client()
            .prove(PartitionMode::OneByOne)
            .await?;
        assert_eq!(job_ids.len(), 1);

        let response = wait_for_prover_job(batch_prover, job_ids[0], Some(TEN_MINS)).await?;
        assert_eq!(response.commitments.len(), 1);
        let batch_proof_output = response
            .proof
            .as_ref()
            .expect("Batch prover job should contain proof")
            .proof_output
            .clone();

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;

        let light_client_proof = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?
            .expect("Light client proof should exist");
        assert_eq!(
            light_client_proof.light_client_proof_output.last_l2_height,
            batch_proof_output.last_l2_height
        );
        assert_eq!(
            light_client_proof.light_client_proof_output.l2_state_root,
            batch_proof_output.final_state_root()
        );
        assert_eq!(
            light_client_proof
                .light_client_proof_output
                .last_sequencer_commitment_index,
            batch_proof_output.sequencer_commitment_index_range.1
        );

        let input_response = light_client_prover
            .client
            .http_client()
            .create_light_client_circuit_input(U64::from(batch_proof_l1_height))
            .await?;

        let expected_l1_hash = da
            .get_block_hash(batch_proof_l1_height)
            .await?
            .as_raw_hash()
            .to_byte_array();
        assert_eq!(input_response.l1_height.to::<u64>(), batch_proof_l1_height);
        assert_eq!(input_response.l1_hash, expected_l1_hash);
        assert!(!input_response.input.is_empty());

        let circuit_input =
            LightClientCircuitInput::<BitcoinSpec>::try_from_slice(&input_response.input)?;

        let input_l1_hash: [u8; 32] = circuit_input.da_block_header.hash().into();
        assert_eq!(
            circuit_input.da_block_header.height(),
            batch_proof_l1_height
        );
        assert_eq!(input_l1_hash, input_response.l1_hash);
        assert_eq!(
            circuit_input.light_client_proof_method_id,
            citrea_sp1_light_client::LIGHT_CLIENT_PROOF_BITCOIN_ID
        );
        assert!(circuit_input.previous_light_client_proof.is_some());

        for (invalid_l1_height, expected_error) in [
            (0, "before initial DA height"),
            (batch_proof_l1_height + 2, "future L1 block"),
        ] {
            let result = light_client_prover
                .client
                .http_client()
                .create_light_client_circuit_input(U64::from(invalid_l1_height))
                .await;
            assert!(result.is_err());
            let error_msg = result.unwrap_err().to_string();
            assert!(
                error_msg.contains(expected_error),
                "Expected error containing '{expected_error}' for L1 block #{invalid_l1_height}, got: {error_msg}"
            );
        }
        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_create_circuit_input_rpc() -> Result<()> {
    TestCaseRunner::new(LightClientCreateCircuitInputRpcTest)
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
        let Some(ProvingSessionInfo::LocalExecution(stats)) = proving_info else {
            panic!("unexpected proving info type");
        };

        assert!(stats.instruction_count > 0);
        assert!(stats.syscall_count > 0);
        assert!(stats.gas > 0);
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

// Reproduces a light-client prover freeze caused by a prefix-matching DA
// transaction whose witness requires hundreds of thousands of guest reads.

// Keep each input below Bitcoin's 1000-element stack limit.
const FLOOD_INPUTS: usize = 236;
const EMPTIES_PER_INPUT: usize = 992;

const POISON_PROVE_TIMEOUT: Duration = Duration::from_secs(240);

/// Returns the configured binary only when it belongs to this workspace.
fn citrea_path_for_witness_flood_test() -> PathBuf {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("Failed to find workspace root")
        .to_path_buf();
    let workspace_bin = workspace_root.join("target").join("debug").join("citrea");

    match std::env::var("CITREA_E2E_TEST_BINARY") {
        Ok(p) => {
            let path = PathBuf::from(&p);
            if path.starts_with(&workspace_root) {
                path
            } else {
                eprintln!(
                    "CITREA_E2E_TEST_BINARY={p} is outside this workspace; using {}",
                    workspace_bin.display()
                );
                workspace_bin
            }
        }
        Err(_) => workspace_bin,
    }
}

/// Builds the stack-draining P2TR leaf shared by every flood input.
fn build_stack_drain_leaf(empties_per_input: usize) -> (ScriptBuf, Vec<u8>, ScriptBuf) {
    assert_eq!(
        empties_per_input % 2,
        0,
        "OP_2DROP consumes elements in pairs"
    );

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x11u8; 32]).expect("valid secret key");
    let internal_key = Keypair::from_secret_key(&secp, &sk).x_only_public_key().0;

    let mut builder = ScriptBuilder::new();
    for _ in 0..empties_per_input / 2 {
        builder = builder.push_opcode(OP_2DROP);
    }
    let tapscript = builder.push_opcode(OP_TRUE).into_script();

    let spend_info = TaprootBuilder::new()
        .add_leaf(0, tapscript.clone())
        .expect("add single leaf")
        .finalize(&secp, internal_key)
        .expect("finalize taproot tree");

    let control_block = spend_info
        .control_block(&(tapscript.clone(), LeafVersion::TapScript))
        .expect("control block for leaf")
        .serialize();

    let script_pubkey = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    (tapscript, control_block, script_pubkey)
}

/// Grinds `tx.lock_time` until its wtxid starts with `prefix`.
fn grind_lock_time_for_wtxid_prefix(tx: &mut Transaction, prefix: &[u8]) {
    let serialized = bitcoin::consensus::serialize(&*tx);
    let len = serialized.len();
    assert!(
        len > 4,
        "transaction serialization too short to hold a lock_time"
    );

    // Reuse the hash state before the final blocks containing lock_time.
    let split = ((len - 4) / 64) * 64;
    let mut base = sha256::HashEngine::default();
    base.input(&serialized[..split]);

    let mut tail = serialized[split..].to_vec();
    let lock_time_offset = tail.len() - 4;

    const MAX_ATTEMPTS: u32 = 1 << 24;
    for nonce in 0..MAX_ATTEMPTS {
        tail[lock_time_offset..].copy_from_slice(&nonce.to_le_bytes());
        let mut engine = base.clone();
        engine.input(&tail);
        if sha256d::Hash::from_engine(engine)
            .to_byte_array()
            .starts_with(prefix)
        {
            tx.lock_time = LockTime::from_consensus(nonce);
            assert!(
                tx.compute_wtxid()
                    .to_raw_hash()
                    .to_byte_array()
                    .starts_with(prefix),
                "grinding produced a wtxid that does not match the requested prefix",
            );
            return;
        }
    }
    panic!("failed to grind wtxid prefix {prefix:?} within {MAX_ATTEMPTS} attempts");
}

struct LightClientProverWitnessFloodFreezeTest;

#[async_trait]
impl TestCase for LightClientProverWitnessFloodFreezeTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            with_full_node: false,
            mode: CitreaMode::Dev,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig::default()
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(125)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        // Fund the shared stack-drain P2TR leaf.
        let (tapscript, control_block, flood_spk) = build_stack_drain_leaf(EMPTIES_PER_INPUT);

        let funding_template = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: (0..FLOOD_INPUTS)
                .map(|_| TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: flood_spk.clone(),
                })
                .collect(),
        };

        // rust-bitcoin gives input-less transactions a witness marker that bitcoind
        // rejects, so encode this funding template in legacy form.
        let mut legacy_template = Vec::new();
        funding_template
            .version
            .consensus_encode(&mut legacy_template)
            .unwrap();
        funding_template
            .input
            .consensus_encode(&mut legacy_template)
            .unwrap();
        funding_template
            .output
            .consensus_encode(&mut legacy_template)
            .unwrap();
        funding_template
            .lock_time
            .consensus_encode(&mut legacy_template)
            .unwrap();
        let funded = da
            .fund_raw_transaction(&legacy_template, None, Some(false))
            .await?;
        let funded_tx: Transaction = bitcoin::consensus::deserialize(&funded.hex)?;
        let signed = da
            .sign_raw_transaction_with_wallet(&funded_tx, None, None)
            .await?;
        let funding_tx: Transaction = bitcoin::consensus::deserialize(&signed.hex)?;
        da.send_raw_transaction(&funding_tx).await?;
        da.generate(1).await?;

        let funding_txid = funding_tx.compute_txid();
        let flood_utxos: Vec<OutPoint> = funding_tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, out)| out.script_pubkey == flood_spk)
            .map(|(vout, _)| OutPoint {
                txid: funding_txid,
                vout: vout as u32,
            })
            .collect();
        assert_eq!(
            flood_utxos.len(),
            FLOOD_INPUTS,
            "funding tx did not create the expected number of flood outputs"
        );

        // Each script-path spend carries empty elements plus the script and control block.
        let mut flood_witness = Witness::new();
        for _ in 0..EMPTIES_PER_INPUT {
            flood_witness.push(b"");
        }
        flood_witness.push(tapscript.as_bytes());
        flood_witness.push(control_block);

        let total_in = 10_000 * FLOOD_INPUTS as u64;
        let change_addr = da.get_new_address(None, None).await?.assume_checked();
        let mut poison_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: flood_utxos
                .iter()
                .map(|outpoint| TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: flood_witness.clone(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(total_in - 50_000),
                script_pubkey: change_addr.script_pubkey(),
            }],
        };

        // A matching wtxid makes the DA layer include this transaction in the proof.
        grind_lock_time_for_wtxid_prefix(&mut poison_tx, REVEAL_TX_PREFIX);

        let empty_elements = EMPTIES_PER_INPUT * FLOOD_INPUTS;
        let weight = poison_tx.weight().to_wu();
        println!(
            "witness-flood tx: {empty_elements} empty witness elements, {weight} WU, wtxid={}",
            poison_tx.compute_wtxid()
        );
        assert!(
            empty_elements >= 234_000,
            "expected ~234k empty witness elements, got {empty_elements}"
        );
        assert!(
            (390_000..=4_000_000).contains(&weight),
            "expected a ~400k-WU transaction, got {weight} WU"
        );

        // `generateblock` bypasses relay policy while still enforcing consensus.
        let mining_addr = da.get_new_address(None, None).await?.assume_checked();
        let poison_hex = bitcoin::consensus::encode::serialize_hex(&poison_tx);
        da.generate_block(mining_addr.to_string(), vec![poison_hex])
            .await?;

        let poison_l1_height = da.get_block_count().await?;
        let poison_block_hash = da.get_block_hash(poison_l1_height).await?;
        let poison_block = da.get_block(&poison_block_hash).await?;
        let poison_txid = poison_tx.compute_txid();
        assert!(
            poison_block
                .txdata
                .iter()
                .any(|tx| tx.compute_txid() == poison_txid),
            "poison tx was not mined into the block"
        );

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // The unfixed guest times out before advancing past the poisoned block.
        let result = light_client_prover
            .wait_for_l1_height(poison_l1_height, Some(POISON_PROVE_TIMEOUT))
            .await;

        let last_scanned = light_client_prover
            .client
            .ledger_get_last_scanned_l1_height()
            .await
            .unwrap();
        assert!(
            result.is_ok(),
            "light-client prover froze on the witness-flood tx at L1 height {poison_l1_height} \
             (last_scanned={last_scanned}): the completeness proof accepted a prefix-matching \
             transaction padded with {empty_elements} empty witness elements, so the guest never \
             finished proving and the prover queue never advanced past it ({result:?})"
        );

        Ok(())
    }
}

#[test]
fn witness_flood_construction_is_prefix_grindable() {
    let (tapscript, control_block, flood_spk) = build_stack_drain_leaf(EMPTIES_PER_INPUT);
    let mut flood_witness = Witness::new();
    for _ in 0..EMPTIES_PER_INPUT {
        flood_witness.push(b"");
    }
    flood_witness.push(tapscript.as_bytes());
    flood_witness.push(control_block);

    let mut poison_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: (0..FLOOD_INPUTS)
            .map(|i| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([i as u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: flood_witness.clone(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(10_000 * FLOOD_INPUTS as u64 - 50_000),
            script_pubkey: flood_spk,
        }],
    };

    grind_lock_time_for_wtxid_prefix(&mut poison_tx, REVEAL_TX_PREFIX);

    let empty_elements = EMPTIES_PER_INPUT * FLOOD_INPUTS;
    let weight = poison_tx.weight().to_wu();
    assert!(
        empty_elements >= 234_000,
        "expected ~234k empty witness elements, got {empty_elements}"
    );
    assert!(
        (390_000..=4_000_000).contains(&weight),
        "expected a ~400k-WU transaction, got {weight} WU"
    );
}

#[tokio::test]
#[ignore = "resource-intensive witness-flood regression test"]
async fn test_light_client_prover_witness_flood_freeze() -> Result<()> {
    TestCaseRunner::new(LightClientProverWitnessFloodFreezeTest)
        .set_citrea_path(citrea_path_for_witness_flood_test())
        .run()
        .await
}
