use std::sync::Arc;

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use sov_db::ledger_db::LightClientProverLedgerOps;
use sov_rollup_interface::rpc::LightClientProofResponse;

pub struct RpcContext<DB>
where
    DB: LightClientProverLedgerOps + Clone,
{
    pub ledger: DB,
}

/// Creates a shared RpcContext with all required data.
pub fn create_rpc_context<DB: LightClientProverLedgerOps + Clone>(ledger_db: DB) -> RpcContext<DB> {
    RpcContext { ledger: ledger_db }
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
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("{e}",)),
                )
            })?;
        let res = proof.map(LightClientProofResponse::from);
        Ok(res)
    }
}
