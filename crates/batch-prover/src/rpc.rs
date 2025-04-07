#![allow(clippy::type_complexity)]

use std::fmt::Debug;
use std::sync::Arc;

use alloy_primitives::{U32, U64};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::SlotNumber;
use sov_rollup_interface::da::SequencerCommitment;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::prover::ProveRequest;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProverInputResponse {
    pub commitment_range: (U32, U32),
    pub l1_block_height: U64,
    pub encoded_serialized_batch_proof_input: String,
}

pub struct RpcContext<DB>
where
    DB: BatchProverLedgerOps + Clone,
{
    pub ledger_db: DB,
    pub request_tx: mpsc::Sender<ProveRequest>,
}

/// Creates a shared RpcContext with all required data.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn create_rpc_context<DB>(
    ledger_db: DB,
    request_tx: mpsc::Sender<ProveRequest>,
) -> RpcContext<DB>
where
    DB: BatchProverLedgerOps + Clone,
{
    RpcContext {
        ledger_db,
        request_tx,
    }
}

/// Updates the given RpcModule with Prover methods.
pub fn register_rpc_methods<DB>(
    rpc_context: RpcContext<DB>,
    mut rpc_methods: jsonrpsee::RpcModule<()>,
) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError>
where
    DB: BatchProverLedgerOps + Clone + 'static,
{
    let rpc = create_rpc_module::<DB>(rpc_context);
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
    async fn prove(&self) -> RpcResult<Vec<Uuid>>;

    /// Stop further proving jobs to be spawned. Existing jobs will continue.
    #[method(name = "pauseProving")]
    async fn pause_proving(&self) -> RpcResult<()>;

    /// Get commitments by l1 height
    #[method(name = "getCommitmentsByL1")]
    async fn get_commitments_by_l1(
        &self,
        l1_height: u64,
    ) -> RpcResult<Vec<SequencerCommitmentRpcResult>>;

    /// Get commitments by job id
    #[method(name = "getCommitmentsByJob")]
    async fn get_commitments_by_job(
        &self,
        job_id: Uuid,
    ) -> RpcResult<Vec<SequencerCommitmentRpcResult>>;
}

pub struct BatchProverRpcServerImpl<DB>
where
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
{
    context: Arc<RpcContext<DB>>,
}

impl<DB> BatchProverRpcServerImpl<DB>
where
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
{
    pub fn new(context: RpcContext<DB>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl<DB> BatchProverRpcServer for BatchProverRpcServerImpl<DB>
where
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
{
    async fn set_commitments(
        &self,
        commitments: Vec<SequencerCommitmentRpcParam>,
    ) -> RpcResult<()> {
        for commitment in commitments {
            let l1_height = commitment.l1_height;
            let commitment = SequencerCommitment {
                merkle_root: commitment.merkle_root,
                index: commitment.index,
                l2_end_block_number: commitment.l2_end_block_number,
            };

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

    async fn prove(&self) -> RpcResult<Vec<Uuid>> {
        let (result_tx, result_rx) = oneshot::channel();

        if let Err(_) = self
            .context
            .request_tx
            .send(ProveRequest::Prove(result_tx))
            .await
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

    async fn pause_proving(&self) -> RpcResult<()> {
        self.context
            .request_tx
            .send(ProveRequest::Pause)
            .await
            .map_err(|_| internal_rpc_error("Proving request channel is closed"))
    }

    async fn get_commitments_by_l1(
        &self,
        l1_height: u64,
    ) -> RpcResult<Vec<SequencerCommitmentRpcResult>> {
        todo!()
    }

    async fn get_commitments_by_job(
        &self,
        job_id: Uuid,
    ) -> RpcResult<Vec<SequencerCommitmentRpcResult>> {
        todo!()
    }
}

pub fn create_rpc_module<DB>(
    rpc_context: RpcContext<DB>,
) -> jsonrpsee::RpcModule<BatchProverRpcServerImpl<DB>>
where
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
{
    let server = BatchProverRpcServerImpl::new(rpc_context);

    BatchProverRpcServer::into_rpc(server)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerCommitmentRpcParam {
    #[serde(with = "hex::serde")]
    pub merkle_root: [u8; 32],
    pub index: u32,
    pub l2_end_block_number: u64,
    pub l1_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerCommitmentRpcResult {
    #[serde(with = "hex::serde")]
    pub merkle_root: [u8; 32],
    pub index: u32,
    pub l2_end_block_number: u64,
}

fn internal_rpc_error(msg: impl AsRef<str>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG, Some(msg.as_ref()))
}
