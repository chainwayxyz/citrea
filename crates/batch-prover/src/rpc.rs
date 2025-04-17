#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

use alloy_primitives::{U32, U64};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use citrea_primitives::forks::fork_from_block_number;
use citrea_stf::runtime::DefaultContext;
use citrea_stf::verifier::get_last_l1_hash_on_contract;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use risc0_zkvm::{FakeReceipt, InnerReceipt, MaybePruned, ReceiptClaim};
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::batch_proof::StoredBatchProofOutput;
use sov_db::schema::types::{L2BlockNumber, SlotNumber};
use sov_modules_api::{BatchProofCircuitOutputV3, SpecId, Zkvm};
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::{DaTxRequest, SequencerCommitment};
use sov_rollup_interface::rpc::{
    BatchProofResponse, JobRpcResponse, SequencerCommitmentResponse, SequencerCommitmentRpcParam,
};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::batch_proof::output::{BatchProofCircuitOutput, CumulativeStateDiff};
use tokio::sync::{mpsc, oneshot};
use tracing::info;
use uuid::Uuid;

use crate::partition::PartitionMode;
use crate::prover::ProverRequest;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProverInputResponse {
    pub commitment_range: (U32, U32),
    pub l1_block_height: U64,
    pub encoded_serialized_batch_proof_input: String,
}

pub struct RpcContext<Da, DB, Vm>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone,
    Vm: Zkvm + 'static,
{
    pub ledger_db: DB,
    pub request_tx: mpsc::Sender<ProverRequest>,
    pub da_service: Arc<Da>,
    pub storage_manager: ProverStorageManager,
    pub code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
}

/// Creates a shared RpcContext with all required data.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn create_rpc_context<Da, DB, Vm>(
    ledger_db: DB,
    request_tx: mpsc::Sender<ProverRequest>,
    da_service: Arc<Da>,
    storage_manager: ProverStorageManager,
    code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
) -> RpcContext<Da, DB, Vm>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone,
    Vm: Zkvm,
{
    RpcContext {
        ledger_db,
        request_tx,
        da_service,
        storage_manager,
        code_commitments,
    }
}

/// Updates the given RpcModule with Prover methods.
pub fn register_rpc_methods<Da, DB, Vm>(
    rpc_context: RpcContext<Da, DB, Vm>,
    mut rpc_methods: jsonrpsee::RpcModule<()>,
) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + 'static,
    Vm: Zkvm,
{
    let rpc = create_rpc_module(rpc_context);
    rpc_methods.merge(rpc)?;
    Ok(rpc_methods)
}

#[rpc(client, server, namespace = "batchProver")]
pub trait BatchProverRpc {
    /// Manually set commitments. It overrides the commitment already if exists, so use with caution.
    #[method(name = "setCommitments")]
    async fn set_commitments(&self, commitments: Vec<SequencerCommitmentRpcParam>)
        -> RpcResult<()>;

    /// Manually signal proving. This rpc triggers a proving signal with the difference that sampling will be ignored.
    #[method(name = "prove")]
    async fn prove(&self, mode: PartitionMode) -> RpcResult<Vec<Uuid>>;

    /// Simulate proving by collecting output from the execution in native, and submit the fake proof to DA.
    #[method(name = "submitFakeProof")]
    async fn submit_fake_proof(
        &self,
        index_start: u32,
        index_end: u32,
    ) -> RpcResult<BatchProofResponse>;

    /// Stop further proving jobs to be spawned. Existing jobs will continue.
    #[method(name = "pauseProving")]
    async fn pause_proving(&self) -> RpcResult<()>;

    /// Create circuit input for the given commitment index range start..=end
    #[method(name = "createCircuitInput")]
    async fn create_circuit_input(
        &self,
        index_start: u32,
        index_end: u32,
        mode: PartitionMode,
    ) -> RpcResult<Vec<String>>;

    /// Get job details by job id. If proof is null, it means job is still being proven,
    /// if proof exists but l1_tx_id is 0, it means job is being submitted to L1.
    #[method(name = "getProvingJob")]
    async fn get_proving_job(&self, job_id: Uuid) -> RpcResult<Option<JobRpcResponse>>;

    /// Gets last `count` number of job ids. Returns ids in descending order, so latest job is the first index.
    #[method(name = "getProvingJobs")]
    async fn get_proving_jobs(&self, count: usize) -> RpcResult<Vec<Uuid>>;

    /// Gets proving job details of the commitment index.
    #[method(name = "getProvingJobOfCommitment")]
    async fn get_proving_job_of_commitment(&self, index: u32) -> RpcResult<Option<JobRpcResponse>>;

    /// Gets commitment indices seen in the L1 block
    #[method(name = "getCommitmentIndicesByL1")]
    async fn get_commitment_indices_by_l1(&self, l1_height: u64) -> RpcResult<Option<Vec<u32>>>;
}

pub struct BatchProverRpcServerImpl<Da, DB, Vm>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: Zkvm + 'static,
{
    context: Arc<RpcContext<Da, DB, Vm>>,
}

impl<Da, DB, Vm> BatchProverRpcServerImpl<Da, DB, Vm>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: Zkvm + 'static,
{
    pub fn new(context: RpcContext<Da, DB, Vm>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl<Da, DB, Vm> BatchProverRpcServer for BatchProverRpcServerImpl<Da, DB, Vm>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: Zkvm + 'static,
{
    async fn set_commitments(
        &self,
        commitments: Vec<SequencerCommitmentRpcParam>,
    ) -> RpcResult<()> {
        for commitment in commitments {
            let l1_height = commitment.l1_height.to::<u64>();
            let commitment = SequencerCommitment {
                merkle_root: commitment.merkle_root,
                index: commitment.index.to::<u32>(),
                l2_end_block_number: commitment.l2_end_block_number.to::<u64>(),
            };

            info!(
                "Overriding sequencer commitment, index={} merkle_root={} l2_end_height={} l1_height={}",
                commitment.index,
                hex::encode(commitment.merkle_root),
                commitment.l2_end_block_number,
                l1_height,
            );

            self.context
                .ledger_db
                .put_commitment_by_index(&commitment)
                .map_err(|e| internal_rpc_error(e.to_string()))?;
            // This might cause some duplicate commitment indices appear in l1 -> index table which is ok
            self.context
                .ledger_db
                .put_commitment_index_by_l1(SlotNumber(l1_height), commitment.index)
                .map_err(|e| internal_rpc_error(e.to_string()))?;
            self.context
                .ledger_db
                .put_prover_pending_commitment(commitment.index)
                .map_err(|e| internal_rpc_error(e.to_string()))?;
        }

        Ok(())
    }

    async fn prove(&self, mode: PartitionMode) -> RpcResult<Vec<Uuid>> {
        let (result_tx, result_rx) = oneshot::channel();

        if self
            .context
            .request_tx
            .send(ProverRequest::Prove(mode, result_tx))
            .await
            .is_err()
        {
            return Err(internal_rpc_error("Proving request channel is closed"));
        }

        let Ok(job_ids) = result_rx.await else {
            return Err(internal_rpc_error(
                "Proving request failed for some reason, check logs for details",
            ));
        };

        Ok(job_ids)
    }

    async fn submit_fake_proof(
        &self,
        index_start: u32,
        index_end: u32,
    ) -> RpcResult<BatchProofResponse> {
        info!(
            "Submitting fake proof for commitment index range [{},{}]",
            index_start, index_end
        );

        let ledger_db = &self.context.ledger_db;

        if index_start > index_end {
            return Err(internal_rpc_error("Invalid index range"));
        }
        // don't allow first commitment index to be called through this rpc as it requires extra handling
        if index_start <= 1 {
            return Err(internal_rpc_error(
                "submitFakeProof rpc supports only index_start > 1",
            ));
        }

        let previous_commitment = ledger_db
            .get_commitment_by_index(index_start - 1)
            .map_err(|e| internal_rpc_error(e.to_string()))?
            .ok_or_else(|| internal_rpc_error("Missing previous commitment index"))?;

        let commitments = ledger_db
            .get_commitment_by_range(index_start..=index_end)
            .map_err(|e| internal_rpc_error(e.to_string()))?;
        if commitments.len() as u32 != index_end - index_start + 1 {
            return Err(internal_rpc_error(
                "Missing some commitment indices from the range",
            ));
        }

        let last_commitment = commitments.last().expect("Already ensured");
        let last_l2_block = ledger_db
            .get_l2_block_by_number(&L2BlockNumber(last_commitment.l2_end_block_number))
            .map_err(|e| internal_rpc_error(e.to_string()))?
            .ok_or_else(|| internal_rpc_error("Not synced up to latest L2 block yet"))?;

        let initial_state_root = ledger_db
            .get_l2_state_root(previous_commitment.l2_end_block_number)
            .map_err(|e| internal_rpc_error(e.to_string()))?
            .expect("Initial L2 state root must exist");

        let mut start_l2_height = previous_commitment.l2_end_block_number + 1;
        let mut sequencer_commitment_hashes = Vec::with_capacity(commitments.len());
        let mut state_roots = Vec::with_capacity(commitments.len() + 1);
        state_roots.push(initial_state_root);

        let mut cumulative_state_diff = CumulativeStateDiff::new();
        for commitment in commitments.iter() {
            let end_l2_height = commitment.l2_end_block_number;

            for l2_height in start_l2_height..=end_l2_height {
                let state_diff = ledger_db
                    .get_l2_state_diff(L2BlockNumber(l2_height))
                    .map_err(|e| internal_rpc_error(e.to_string()))?
                    .expect("L2 state diff must exist");
                cumulative_state_diff.extend(state_diff);
            }

            sequencer_commitment_hashes.push(commitment.serialize_and_calculate_sha_256());

            let end_state_root = ledger_db
                .get_l2_state_root(end_l2_height)
                .map_err(|e| internal_rpc_error(e.to_string()))?
                .expect("L2 state root must exist");
            state_roots.push(end_state_root);

            start_l2_height = end_l2_height + 1;
        }

        let storage = self
            .context
            .storage_manager
            .create_storage_for_l2_height(last_l2_block.height + 1);
        let last_l1_hash_on_contract = get_last_l1_hash_on_contract::<DefaultContext>(
            Default::default(),
            storage,
            &mut Default::default(),
            [0; 32],
        );

        let output = BatchProofCircuitOutput::V3(BatchProofCircuitOutputV3 {
            state_roots,
            final_l2_block_hash: last_l2_block.hash,
            state_diff: cumulative_state_diff,
            last_l2_height: last_l2_block.height,
            sequencer_commitment_hashes,
            sequencer_commitment_index_range: (index_start, index_end),
            last_l1_hash_on_bitcoin_light_client_contract: last_l1_hash_on_contract,
            previous_commitment_index: Some(previous_commitment.index),
            previous_commitment_hash: Some(previous_commitment.serialize_and_calculate_sha_256()),
        });

        let output_serialized = borsh::to_vec(&output).expect("Output serialization cannot fail");

        let spec_id = fork_from_block_number(last_l2_block.height).spec_id;
        let method_id: [u32; 8] = self
            .context
            .code_commitments
            .get(&spec_id)
            .expect("Spec for L2 block must exist")
            .clone()
            .into();

        let claim = MaybePruned::Value(ReceiptClaim::ok(method_id, output_serialized));
        let fake_receipt = FakeReceipt::new(claim);
        // Receipt with verifiable claim
        let receipt = InnerReceipt::Fake(fake_receipt);
        let proof = bincode::serialize(&receipt).expect("Receipt serialization cannot fail");

        let tx_id = self
            .context
            .da_service
            .send_transaction(DaTxRequest::ZKProof(proof.clone()))
            .await
            .map_err(|e| internal_rpc_error(e.to_string()))?;

        Ok(BatchProofResponse {
            l1_tx_id: Some(tx_id.into()),
            proof,
            proof_output: StoredBatchProofOutput::from(output).into(),
        })
    }

    async fn pause_proving(&self) -> RpcResult<()> {
        self.context
            .request_tx
            .send(ProverRequest::Pause)
            .await
            .map_err(|_| internal_rpc_error("Proving request channel is closed"))
    }

    async fn create_circuit_input(
        &self,
        index_start: u32,
        index_end: u32,
        mode: PartitionMode,
    ) -> RpcResult<Vec<String>> {
        let commitments = self
            .context
            .ledger_db
            .get_commitment_by_range(index_start..=index_end)
            .map_err(|e| internal_rpc_error(e.to_string()))?;

        let (result_tx, result_rx) = oneshot::channel();

        if self
            .context
            .request_tx
            .send(ProverRequest::CreateInput(mode, commitments, result_tx))
            .await
            .is_err()
        {
            return Err(internal_rpc_error("Proving request channel is closed"));
        }

        let Ok(raw_inputs) = result_rx.await else {
            return Err(internal_rpc_error(
                "Proving request failed for some reason, check logs for details",
            ));
        };

        let mut b64_inputs = Vec::with_capacity(raw_inputs.len());
        let unix_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for (i, raw_input) in raw_inputs.into_iter().enumerate() {
            if let Ok(backup_dir) = env::var("TX_BACKUP_DIR") {
                let input_path = Path::new(&backup_dir)
                    .join(format!("{}-rpc-proof-input-{}.bin", unix_nanos, i));
                fs::write(input_path, &raw_input).expect("Proof input write cannot fail");
            }
            b64_inputs.push(BASE64_STANDARD.encode(&raw_input));
        }

        Ok(b64_inputs)
    }

    async fn get_proving_job(&self, job_id: Uuid) -> RpcResult<Option<JobRpcResponse>> {
        let ledger_db = &self.context.ledger_db;

        let Some(commitment_indices) = ledger_db
            .get_commitment_indices_by_job_id(job_id)
            .map_err(|e| internal_rpc_error(e.to_string()))?
        else {
            return Ok(None);
        };

        let mut commitments = Vec::with_capacity(commitment_indices.len());
        for index in commitment_indices {
            let commitment = ledger_db
                .get_commitment_by_index(index)
                .map_err(|e| internal_rpc_error(e.to_string()))?
                .expect("Commitment must exist");
            commitments.push(SequencerCommitmentResponse {
                merkle_root: commitment.merkle_root,
                index: commitment.index.try_into().unwrap(),
                l2_end_block_number: commitment.l2_end_block_number.try_into().unwrap(),
            });
        }

        let stored_proof = ledger_db
            .get_proof_by_job_id(job_id)
            .map_err(|e| internal_rpc_error(e.to_string()))?;

        Ok(Some(JobRpcResponse {
            id: job_id,
            commitments,
            proof: stored_proof.map(Into::into),
        }))
    }

    async fn get_proving_jobs(&self, count: usize) -> RpcResult<Vec<Uuid>> {
        Ok(self
            .context
            .ledger_db
            .get_latest_job_ids(count)
            .map_err(|e| internal_rpc_error(e.to_string()))?)
    }

    async fn get_proving_job_of_commitment(&self, index: u32) -> RpcResult<Option<JobRpcResponse>> {
        let job_id = self
            .context
            .ledger_db
            .get_job_id_by_commitment_index(index)
            .map_err(|e| internal_rpc_error(e.to_string()))?;
        match job_id {
            Some(job_id) => self.get_proving_job(job_id).await,
            None => Ok(None),
        }
    }

    async fn get_commitment_indices_by_l1(&self, l1_height: u64) -> RpcResult<Option<Vec<u32>>> {
        self.context
            .ledger_db
            .get_prover_commitment_indices_by_l1(SlotNumber(l1_height))
            .map_err(|e| internal_rpc_error(e.to_string()))
    }
}

pub fn create_rpc_module<Da, DB, Vm>(
    rpc_context: RpcContext<Da, DB, Vm>,
) -> jsonrpsee::RpcModule<BatchProverRpcServerImpl<Da, DB, Vm>>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: Zkvm + 'static,
{
    let server = BatchProverRpcServerImpl::new(rpc_context);

    BatchProverRpcServer::into_rpc(server)
}

fn internal_rpc_error(msg: impl AsRef<str>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG, Some(msg.as_ref()))
}
