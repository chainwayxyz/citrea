use std::sync::Arc;

use citrea_common::rpc::utils::internal_rpc_error;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use sov_db::ledger_db::LightClientProverLedgerOps;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{Spec, WorkingSet};
use sov_rollup_interface::rpc::{BatchProofMethodIdRpcResponse, LightClientProofResponse};
use sov_state::ProverStorage;

use crate::circuit::accessors::BatchProofMethodIdAccessor;

pub struct RpcContext<DB>
where
    DB: LightClientProverLedgerOps + Clone,
{
    pub ledger: DB,
    pub storage: <DefaultContext as Spec>::Storage,
}

/// Creates a shared RpcContext with all required data.
pub fn create_rpc_context<DB: LightClientProverLedgerOps + Clone>(
    ledger_db: DB,
    storage: <DefaultContext as Spec>::Storage,
) -> RpcContext<DB> {
    RpcContext {
        ledger: ledger_db,
        storage,
    }
}

pub fn create_rpc_module<DB>(
    rpc_context: RpcContext<DB>,
) -> jsonrpsee::RpcModule<LightClientProverRpcServerImpl<DB>>
where
    DB: LightClientProverLedgerOps + Clone + Send + Sync + 'static,
{
    let server = LightClientProverRpcServerImpl::new(rpc_context);

    LightClientProverRpcServer::into_rpc(server)
}

/// Updates the given RpcModule with Prover methods.
pub fn register_rpc_methods<DB: LightClientProverLedgerOps + Clone + 'static>(
    mut rpc_methods: jsonrpsee::RpcModule<()>,
    rpc_context: RpcContext<DB>,
) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
    let rpc = create_rpc_module(rpc_context);
    rpc_methods.merge(rpc)?;
    Ok(rpc_methods)
}

#[rpc(client, server, namespace = "lightClientProver")]
pub trait LightClientProverRpc {
    /// Generate state transition data for the given L1 block height, and return the data as a borsh serialized hex string.
    #[method(name = "getLightClientProofByL1Height")]
    async fn get_light_client_proof_by_l1_height(
        &self,
        l1_height: u64,
    ) -> RpcResult<Option<LightClientProofResponse>>;

    /// Gets the current method ids saved light client provers jmt state
    #[method(name = "getBatchProofMethodIds")]
    async fn get_batch_proof_method_ids(&self) -> RpcResult<Vec<BatchProofMethodIdRpcResponse>>;
}

pub struct LightClientProverRpcServerImpl<DB>
where
    DB: LightClientProverLedgerOps + Clone + Send + Sync + 'static,
{
    pub context: Arc<RpcContext<DB>>,
}

impl<DB> LightClientProverRpcServerImpl<DB>
where
    DB: LightClientProverLedgerOps + Clone + Send + Sync + 'static,
{
    pub fn new(context: RpcContext<DB>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl<DB> LightClientProverRpcServer for LightClientProverRpcServerImpl<DB>
where
    DB: LightClientProverLedgerOps + Clone + Send + Sync + 'static,
{
    async fn get_light_client_proof_by_l1_height(
        &self,
        l1_height: u64,
    ) -> RpcResult<Option<LightClientProofResponse>> {
        let proof = self
            .context
            .ledger
            .get_light_client_proof_data_by_l1_height(l1_height)
            .map_err(internal_rpc_error)?;
        let res = proof.map(LightClientProofResponse::from);
        Ok(res)
    }

    async fn get_batch_proof_method_ids(&self) -> RpcResult<Vec<BatchProofMethodIdRpcResponse>> {
        let mut working_set = WorkingSet::new(self.context.storage.clone());

        let method_ids = BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set)
            .unwrap_or_default()
            .into_iter()
            .map(|id| BatchProofMethodIdRpcResponse {
                method_id: id.1.into(),
                height: alloy_primitives::U64::from(id.0),
            })
            .collect::<Vec<_>>();

        Ok(method_ids)
    }
}
