//! Query interface for the L2 Block Rule Enforcer module.
//!
//! This module provides RPC methods for querying the current state of the rule enforcer,
//! including the maximum L2 blocks per L1 configuration and the latest block timestamp.

use jsonrpsee::core::RpcResult;
use sov_modules_api::macros::rpc_gen;
use sov_modules_api::{Context, DaSpec, StateValueAccessor, WorkingSet};

use crate::L2BlockRuleEnforcer;

/// RPC interface for the L2 Block Rule Enforcer module.
///
/// This implementation provides read-only access to the rule enforcer's state
/// through JSON-RPC methods. All methods are available under the
/// "L2BlockRuleEnforcer" namespace.
#[rpc_gen(client, server, namespace = "L2BlockRuleEnforcer")]
impl<C: Context, Da: DaSpec> L2BlockRuleEnforcer<C, Da> {
    /// Gets the maximum number of L2 blocks allowed per L1 block.
    ///
    /// This value determines how many L2 blocks the sequencer can publish
    /// for each L1 block before the rule enforcer rejects further blocks.
    ///
    /// # Arguments
    ///
    /// * `working_set` - The working set for reading state
    ///
    /// # Returns
    ///
    /// Returns the current maximum L2 blocks per L1 configuration as a `u32`.
    ///
    /// # Panics
    ///
    /// Panics if the rule enforcer data has not been initialized during genesis.
    #[rpc_method(name = "getMaxL2BlocksPerL1")]
    pub fn get_max_l2_blocks_per_l1(
        &self,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> RpcResult<u32> {
        Ok(self
            .data
            .get(working_set)
            .expect("Max L2 blocks per L1 must be set")
            .max_l2_blocks_per_l1)
    }

    /// Gets the latest block's timestamp.
    ///
    /// This method returns the timestamp of the most recently processed L2 block.
    /// The timestamp is 0 at genesis before any blocks have been processed.
    ///
    /// # Arguments
    ///
    /// * `working_set` - The working set for reading state
    ///
    /// # Returns
    ///
    /// Returns the timestamp of the last processed block as a `u64`.
    /// Returns 0 if no blocks have been processed yet (at genesis).
    ///
    /// # Panics
    ///
    /// Panics if the rule enforcer data has not been initialized during genesis.
    #[rpc_method(name = "getLatestBlockTimestamp")]
    pub fn get_last_timestamp(&self, working_set: &mut WorkingSet<C::Storage>) -> RpcResult<u64> {
        Ok(self
            .data
            .get(working_set)
            .expect("should be set in genesis; qed")
            .last_timestamp)
    }
}
