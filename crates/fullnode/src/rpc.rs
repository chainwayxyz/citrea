use std::sync::Arc;

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use sov_db::ledger_db::NodeLedgerOps;
use sov_db::schema::types::{L2HeightAndIndex, L2HeightStatus};

pub struct RpcContext<DB>
where
    DB: NodeLedgerOps + Clone,
{
    pub ledger: DB,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct L2StatusHeightsByL1Height {
    pub committed: L2HeightAndIndex,
    pub proven: L2HeightAndIndex,
}

pub fn create_rpc_context<DB: NodeLedgerOps + Clone>(ledger_db: DB) -> RpcContext<DB> {
    RpcContext { ledger: ledger_db }
}

pub fn create_rpc_module<DB>(
    rpc_context: RpcContext<DB>,
) -> jsonrpsee::RpcModule<FullNodeRpcServerImpl<DB>>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
{
    let server = FullNodeRpcServerImpl::new(rpc_context);
    FullNodeRpcServer::into_rpc(server)
}

pub fn register_rpc_methods<DB: NodeLedgerOps + Clone + 'static>(
    mut rpc_methods: jsonrpsee::RpcModule<()>,
    rpc_context: RpcContext<DB>,
) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
    let rpc = create_rpc_module(rpc_context);
    rpc_methods.merge(rpc)?;
    Ok(rpc_methods)
}

#[rpc(client, server, namespace = "citrea")]
pub trait FullNodeRpc {
    /// Get the last L2 height that has been committed
    #[method(name = "getLastCommittedL2Height")]
    async fn get_last_committed_l2_height(&self) -> RpcResult<Option<L2HeightAndIndex>>;

    /// Get the last L2 height that has been proven
    #[method(name = "getLastProvenL2Height")]
    async fn get_last_proven_l2_height(&self) -> RpcResult<Option<L2HeightAndIndex>>;

    /// Get the last commited and proven L2 heights up to a specific L1 height
    #[method(name = "getL2StatusHeightsByL1Height")]
    async fn get_l2_status_heights_by_l1_height(
        &self,
        l1_height: u64,
    ) -> RpcResult<L2StatusHeightsByL1Height>;
}

pub struct FullNodeRpcServerImpl<DB>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
{
    pub context: Arc<RpcContext<DB>>,
}

impl<DB> FullNodeRpcServerImpl<DB>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
{
    pub fn new(context: RpcContext<DB>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl<DB> FullNodeRpcServer for FullNodeRpcServerImpl<DB>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
{
    async fn get_last_committed_l2_height(&self) -> RpcResult<Option<L2HeightAndIndex>> {
        self.context
            .ledger
            .get_highest_l2_height_for_status(L2HeightStatus::Committed, None)
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("Failed to get committed L2 height: {e}")),
                )
            })
    }

    async fn get_last_proven_l2_height(&self) -> RpcResult<Option<L2HeightAndIndex>> {
        self.context
            .ledger
            .get_highest_l2_height_for_status(L2HeightStatus::Proven, None)
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("Failed to get proven L2 height: {e}")),
                )
            })
    }

    async fn get_l2_status_heights_by_l1_height(
        &self,
        l1_height: u64,
    ) -> RpcResult<L2StatusHeightsByL1Height> {
        let (committed, proven) = self
            .context
            .ledger
            .get_l2_status_heights_by_l1_height(l1_height)
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("Failed to get L2 status heights by L1 height: {e}")),
                )
            })?;

        Ok(L2StatusHeightsByL1Height {
            committed: committed.unwrap_or_default(),
            proven: proven.unwrap_or_default(),
        })
    }
}
