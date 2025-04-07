#![allow(clippy::type_complexity)]

use std::fmt::Debug;
use std::sync::Arc;

use alloy_primitives::{U32, U64};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::BatchProverLedgerOps;
use tokio::sync::mpsc;

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
    /// Manually signal proving. This rpc triggers a proving signal with the difference that sampling will be ignored.
    #[method(name = "prove")]
    async fn prove(&self) -> RpcResult<()>;
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
    async fn prove(&self) -> RpcResult<()> {
        // let l1_block: <Da as DaService>::FilteredBlock = self
        //     .context
        //     .da_service
        //     .get_block_at(l1_height)
        //     .await
        //     .map_err(|e| {
        //         ErrorObjectOwned::owned(
        //             INTERNAL_ERROR_CODE,
        //             INTERNAL_ERROR_MSG,
        //             Some(format!("{e}",)),
        //         )
        //     })?;

        // let (sequencer_commitments, inputs) = data_to_prove::<Da, DB>(
        //     self.context.da_service.clone(),
        //     self.context.ledger.clone(),
        //     &self.context.storage_manager,
        //     self.context.sequencer_pub_key.clone(),
        //     self.context.sequencer_da_pub_key.clone(),
        //     &l1_block,
        //     group_commitments,
        // )
        // .await
        // .map_err(|e| {
        //     ErrorObjectOwned::owned(
        //         INTERNAL_ERROR_CODE,
        //         INTERNAL_ERROR_MSG,
        //         Some(format!("{e}",)),
        //     )
        // })?;

        // prove_l1::<Da, Vm, DB>(
        //     self.context.prover_service.clone(),
        //     self.context.ledger.clone(),
        //     self.context.code_commitments_by_spec.clone(),
        //     self.context.elfs_by_spec.clone(),
        //     &l1_block,
        //     sequencer_commitments,
        //     inputs,
        // )
        // .await
        // .map_err(|e| {
        //     ErrorObjectOwned::owned(
        //         INTERNAL_ERROR_CODE,
        //         INTERNAL_ERROR_MSG,
        //         Some(format!("{e}",)),
        //     )
        // })?;

        // Ok(())
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
