//! RPC interface for the fullnode
//!
//! This module provides a subset of the fullnode's RPC functionality, specifically focused on
//! tracking L2 block finality with respect to L1 blocks. This includes methods to query the
//! commitment and proof status of L2 blocks relative to L1 blocks.
//!
//! Note that this module only contains finality-tracking RPC methods. The majority of the
//! fullnode's RPC functionality (such as transaction submission, state queries, and block
//! information) is defined in other modules of the codebase.

use std::sync::Arc;

use alloy_primitives::U64;
use citrea_common::rpc::utils::internal_rpc_error;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use sov_db::ledger_db::NodeLedgerOps;
use sov_db::schema::types::{L2HeightAndIndex, L2HeightStatus};

/// Context containing shared data needed for RPC method implementations
pub struct RpcContext<DB>
where
    DB: NodeLedgerOps + Clone,
{
    /// Database for ledger operations
    pub ledger: DB,
}

/// Response type containing L2 block heights and their status relative to a L1 height.
/// This type tracks two key stages of L2 block finality:
/// - Committed: When a commitment to the L2 blocks are posted to L1 by the sequencer
/// - Proven: When validity proofs for L2 blocks are posted to L1 by the batch prover
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct L2StatusHeightsByL1Height {
    /// The L2 block height that has been committed to L1 by the sequencer at this L1 height.
    /// Committed blocks have their data available on L1 but their validity has not yet been proven.
    pub committed: L2HeightAndIndex,
    /// The L2 block height that has been proven valid on L1 by the batch prover at this L1 height.
    /// Proven blocks have had their validity mathematically verified through ZK proofs.
    pub proven: L2HeightAndIndex,
}

/// Creates a new RPC context with the provided ledger database
///
/// # Arguments
/// * `ledger_db` - Database instance for ledger operations
pub fn create_rpc_context<DB: NodeLedgerOps + Clone>(ledger_db: DB) -> RpcContext<DB> {
    RpcContext { ledger: ledger_db }
}

/// Creates an RPC module with fullnode methods
///
/// # Arguments
/// * `rpc_context` - Context containing shared data for RPC methods
///
/// # Type Parameters
/// * `DB` - Database type implementing NodeLedgerOps
pub fn create_rpc_module<DB>(
    rpc_context: RpcContext<DB>,
) -> jsonrpsee::RpcModule<FullNodeRpcServerImpl<DB>>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
{
    let server = FullNodeRpcServerImpl::new(rpc_context);
    FullNodeRpcServer::into_rpc(server)
}

/// Registers fullnode RPC methods with an existing RPC module
///
/// # Arguments
/// * `rpc_methods` - Existing RPC module to extend
/// * `rpc_context` - Context containing shared data for RPC methods
///
/// # Returns
/// The updated RPC module or a registration error
pub fn register_rpc_methods<DB: NodeLedgerOps + Clone + 'static>(
    mut rpc_methods: jsonrpsee::RpcModule<()>,
    rpc_context: RpcContext<DB>,
) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
    let rpc = create_rpc_module(rpc_context);
    rpc_methods.merge(rpc)?;
    Ok(rpc_methods)
}

/// Interface definition for fullnode RPC methods
///
/// This trait defines the available RPC methods that can be called
/// to query information about block status and synchronization progress.
#[rpc(client, server, namespace = "citrea")]
pub trait FullNodeRpc {
    /// Get the last L2 height that has been committed
    #[method(name = "getLastCommittedL2Height")]
    async fn get_last_committed_l2_height(&self) -> RpcResult<Option<L2HeightAndIndex>>;

    /// Get the last L2 height that has been proven
    #[method(name = "getLastProvenL2Height")]
    async fn get_last_proven_l2_height(&self) -> RpcResult<Option<L2HeightAndIndex>>;

    /// Get the last committed and proven L2 heights up to a specific L1 height
    ///
    /// # Arguments
    /// * `l1_height` - The L1 block height to query status for
    #[method(name = "getL2StatusHeightsByL1Height")]
    async fn get_l2_status_heights_by_l1_height(
        &self,
        l1_height: U64,
    ) -> RpcResult<L2StatusHeightsByL1Height>;
}

/// Server implementation of the fullnode RPC interface
pub struct FullNodeRpcServerImpl<DB>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
{
    /// Shared RPC context containing the ledger database
    pub context: Arc<RpcContext<DB>>,
}

impl<DB> FullNodeRpcServerImpl<DB>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
{
    /// Creates a new fullnode RPC server instance
    ///
    /// # Arguments
    /// * `context` - Shared context containing the ledger database
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
            .map_err(|e| internal_rpc_error(format!("Failed to get committed L2 height: {e}")))
    }

    async fn get_last_proven_l2_height(&self) -> RpcResult<Option<L2HeightAndIndex>> {
        self.context
            .ledger
            .get_highest_l2_height_for_status(L2HeightStatus::Proven, None)
            .map_err(|e| internal_rpc_error(format!("Failed to get proven L2 height: {e}")))
    }

    async fn get_l2_status_heights_by_l1_height(
        &self,
        l1_height: U64,
    ) -> RpcResult<L2StatusHeightsByL1Height> {
        let (committed, proven) = self
            .context
            .ledger
            .get_l2_status_heights_by_l1_height(l1_height.to())
            .map_err(|e| {
                internal_rpc_error(format!("Failed to get L2 status heights by L1 height: {e}"))
            })?;

        Ok(L2StatusHeightsByL1Height {
            committed: committed.unwrap_or_default(),
            proven: proven.unwrap_or_default(),
        })
    }
}
