//! RPC interface for the fullnode
//!
//! This module provides a subset of the fullnode's RPC functionality, specifically focused on
//! tracking L2 block finality with respect to L1 blocks. This includes methods to query the
//! commitment and proof status of L2 blocks relative to L1 blocks, as well as re-executing
//! historical L2 blocks to produce their state diffs.
//!
//! Note that the majority of the fullnode's RPC functionality (such as transaction submission,
//! state queries, and block information) is defined in other modules of the codebase.

use std::collections::BTreeMap;
use std::sync::Arc;

use alloy_primitives::{Bytes, B256, U64};
use citrea_common::l2::execute_l2_block;
use citrea_common::rpc::utils::internal_rpc_error;
use citrea_common::utils::decode_sov_tx_and_update_short_header_proofs;
use citrea_primitives::forks::fork_from_block_number;
use citrea_stf::runtime::CitreaRuntime;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{ErrorObjectOwned, INVALID_PARAMS_CODE, INVALID_PARAMS_MSG};
use sov_db::ledger_db::NodeLedgerOps;
use sov_db::schema::types::{L2BlockNumber, L2HeightAndIndex, L2HeightStatus};
use sov_keys::default_signature::K256PublicKey;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::L2Block;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::services::da::DaService;

/// Context containing shared data needed for RPC method implementations
pub struct RpcContext<DB, Da>
where
    DB: NodeLedgerOps + Clone,
    Da: DaService,
{
    /// Database for ledger operations
    pub ledger: DB,
    /// Manager for creating historical storage views for block re-execution
    pub storage_manager: ProverStorageManager,
    /// Sequencer public key used for block signature verification during re-execution
    pub sequencer_pub_key: K256PublicKey,
    /// DA service, used to backfill short header proofs if missing
    pub da_service: Arc<Da>,
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

/// A single state diff entry. `value` is `None` when the key was deleted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateDiffEntryResponse {
    /// Raw storage key preimage
    pub key: Bytes,
    /// Codec-encoded value bytes, or `None` if the key was deleted
    pub value: Option<Bytes>,
}

/// Response of `citrea_getStateDiffByBlockNumber`: the state diff produced by re-executing
/// a single L2 block. Entries are deduplicated (last write wins) and sorted by key so that
/// responses from different nodes are directly comparable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockStateDiffResponse {
    /// The re-executed L2 block height
    pub block_number: U64,
    /// Hash of the re-executed block
    pub block_hash: B256,
    /// State root the block was executed against (root of block N-1)
    pub pre_state_root: B256,
    /// State root after re-execution; guaranteed to match the stored root of block N
    pub post_state_root: B256,
    /// The state diff produced by the block
    pub state_diff: Vec<StateDiffEntryResponse>,
}

/// Builds an invalid-params JSON-RPC error
fn invalid_params_error(msg: impl ToString) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        INVALID_PARAMS_CODE,
        INVALID_PARAMS_MSG,
        Some(msg.to_string()),
    )
}

/// Creates a new RPC context with the provided ledger database and re-execution dependencies
///
/// # Arguments
/// * `ledger_db` - Database instance for ledger operations
/// * `storage_manager` - Manager for creating historical storage views
/// * `sequencer_pub_key` - Sequencer public key for block signature verification
/// * `da_service` - DA service used to backfill short header proofs
pub fn create_rpc_context<DB: NodeLedgerOps + Clone, Da: DaService>(
    ledger_db: DB,
    storage_manager: ProverStorageManager,
    sequencer_pub_key: K256PublicKey,
    da_service: Arc<Da>,
) -> RpcContext<DB, Da> {
    RpcContext {
        ledger: ledger_db,
        storage_manager,
        sequencer_pub_key,
        da_service,
    }
}

/// Creates an RPC module with fullnode methods
///
/// # Arguments
/// * `rpc_context` - Context containing shared data for RPC methods
///
/// # Type Parameters
/// * `DB` - Database type implementing NodeLedgerOps
/// * `Da` - Data availability service type
pub fn create_rpc_module<DB, Da>(
    rpc_context: RpcContext<DB, Da>,
) -> jsonrpsee::RpcModule<FullNodeRpcServerImpl<DB, Da>>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
    Da: DaService,
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
pub fn register_rpc_methods<DB: NodeLedgerOps + Clone + 'static, Da: DaService>(
    mut rpc_methods: jsonrpsee::RpcModule<()>,
    rpc_context: RpcContext<DB, Da>,
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

    /// Re-execute the L2 block at the given height against historical state and return
    /// the resulting state diff. Nothing is persisted.
    ///
    /// # Arguments
    /// * `block_number` - The L2 block height to re-execute
    #[method(name = "getStateDiffByBlockNumber")]
    async fn get_state_diff_by_block_number(
        &self,
        block_number: U64,
    ) -> RpcResult<BlockStateDiffResponse>;
}

/// Server implementation of the fullnode RPC interface
pub struct FullNodeRpcServerImpl<DB, Da>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
    Da: DaService,
{
    /// Shared RPC context containing the ledger database and re-execution dependencies
    pub context: Arc<RpcContext<DB, Da>>,
}

impl<DB, Da> FullNodeRpcServerImpl<DB, Da>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
    Da: DaService,
{
    /// Creates a new fullnode RPC server instance
    ///
    /// # Arguments
    /// * `context` - Shared context containing the ledger database
    pub fn new(context: RpcContext<DB, Da>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl<DB, Da> FullNodeRpcServer for FullNodeRpcServerImpl<DB, Da>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
    Da: DaService,
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

    async fn get_state_diff_by_block_number(
        &self,
        block_number: U64,
    ) -> RpcResult<BlockStateDiffResponse> {
        let ctx = &self.context;
        let l2_height: u64 = block_number.to();

        if l2_height == 0 {
            return Err(invalid_params_error(
                "Genesis block cannot be re-executed, height must be >= 1",
            ));
        }

        let head_height = ctx
            .ledger
            .get_head_l2_block_height()
            .map_err(|e| internal_rpc_error(format!("Failed to get head L2 height: {e}")))?
            .unwrap_or(0);
        if l2_height > head_height {
            return Err(invalid_params_error(format!(
                "Block {l2_height} not found, head is {head_height}"
            )));
        }

        // Check if the requested block has been pruned
        if let Some(pruned_height) = ctx
            .ledger
            .get_last_pruned_l2_height()
            .map_err(|e| internal_rpc_error(format!("Failed to get pruned height: {e}")))?
        {
            if l2_height <= pruned_height {
                return Err(invalid_params_error(format!(
                    "State for block {l2_height} has been pruned, node is pruned up to {pruned_height}"
                )));
            }
        }

        let stored_block = ctx
            .ledger
            .get_l2_block_by_number(&L2BlockNumber(l2_height))
            .map_err(|e| internal_rpc_error(format!("Failed to get L2 block: {e}")))?
            .ok_or_else(|| invalid_params_error(format!("Block {l2_height} not found")))?;

        if stored_block.txs.iter().any(|tx| tx.body.is_none()) {
            return Err(internal_rpc_error(
                "Node does not store transaction bodies (include_tx_body = false), cannot re-execute",
            ));
        }

        let block_hash = stored_block.hash;
        let stored_state_root = stored_block.state_root;

        // Check prev hash linkage against block N-1. Block 0 is not stored, so the
        // check is skipped for the first block.
        if l2_height > 1 {
            let prev_block = ctx
                .ledger
                .get_l2_block_by_number(&L2BlockNumber(l2_height - 1))
                .map_err(|e| internal_rpc_error(format!("Failed to get L2 block: {e}")))?
                .ok_or_else(|| {
                    internal_rpc_error(format!("Parent block {} not found", l2_height - 1))
                })?;
            if prev_block.hash != stored_block.prev_hash {
                return Err(internal_rpc_error(format!(
                    "Prev hash mismatch at height {l2_height}"
                )));
            }
        }

        // For height 1 this returns the stored genesis state root
        let pre_state_root = ctx
            .ledger
            .get_l2_state_root(l2_height - 1)
            .map_err(|e| internal_rpc_error(format!("Failed to get state root: {e}")))?
            .ok_or_else(|| {
                internal_rpc_error(format!("State root of block {} not found", l2_height - 1))
            })?;

        let block_response: L2BlockResponse = stored_block
            .try_into()
            .map_err(|e| internal_rpc_error(format!("Failed to convert stored block: {e}")))?;

        // Short header proofs referenced by the block's system txs are already stored for
        // any block the node synced; this backfills from DA only if they are missing.
        decode_sov_tx_and_update_short_header_proofs(
            &block_response,
            &ctx.ledger,
            ctx.da_service.clone(),
        )
        .await
        .map_err(|e| internal_rpc_error(format!("Failed to update short header proofs: {e}")))?;

        let l2_block: L2Block = block_response
            .try_into()
            .map_err(|e| internal_rpc_error(format!("Failed to parse transactions: {e}")))?;

        let current_spec = fork_from_block_number(l2_height).spec_id;

        // Uncommittable storage pinned at the pre-state of block N. Writes made during
        // re-execution only live in this instance's in-memory cache and are dropped with it;
        // finalize_storage is never called (and would panic on uncommittable storage).
        let pre_state = ctx.storage_manager.create_storage_for_l2_height(l2_height);

        let sequencer_pub_key = ctx.sequencer_pub_key.clone();
        let l2_block_result = tokio::task::spawn_blocking(move || {
            let mut stf = StfBlueprint::<
                DefaultContext,
                Da::Spec,
                CitreaRuntime<DefaultContext, Da::Spec>,
            >::new();
            execute_l2_block::<Da>(
                &mut stf,
                &l2_block,
                pre_state,
                current_spec,
                &pre_state_root,
                &sequencer_pub_key,
            )
        })
        .await
        .map_err(|e| internal_rpc_error(format!("Re-execution task failed: {e}")))?
        .map_err(|e| internal_rpc_error(format!("Re-execution failed: {e:?}")))?;

        let computed_root = l2_block_result.state_root_transition.final_root;
        if computed_root != stored_state_root {
            tracing::error!(
                "State diff RPC: re-execution state root mismatch at height {}: computed {}, stored {}",
                l2_height,
                B256::from(computed_root),
                B256::from(stored_state_root),
            );
            return Err(internal_rpc_error(format!(
                "Re-execution state root mismatch at height {l2_height}: computed {}, stored {}",
                B256::from(computed_root),
                B256::from(stored_state_root),
            )));
        }

        // The per-block diff coming out of the STF is already deduplicated and key-sorted
        // (it is built from a BTreeMap-backed cache log), but that is a representation
        // detail; normalize here so the response contract holds regardless.
        let deduped: BTreeMap<_, _> = l2_block_result.state_diff.into_iter().collect();
        let state_diff = deduped
            .into_iter()
            .map(|(key, value)| StateDiffEntryResponse {
                key: Bytes::copy_from_slice(&key),
                value: value.map(|v| Bytes::copy_from_slice(&v)),
            })
            .collect();

        Ok(BlockStateDiffResponse {
            block_number,
            block_hash: B256::from(block_hash),
            pre_state_root: B256::from(pre_state_root),
            post_state_root: B256::from(computed_root),
            state_diff,
        })
    }
}
