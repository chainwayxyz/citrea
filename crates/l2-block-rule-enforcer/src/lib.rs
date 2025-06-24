//! # L2 Block Rule Enforcer
//!
//! The L2 Block Rule Enforcer is a critical component of the Citrea rollup that ensures proper
//! sequencer behavior by enforcing rules about L2 block production and timing.
//!
//! ## Purpose
//!
//! This module prevents the sequencer from:
//! 1. **Publishing too many L2 blocks per L1 block** - Limits the number of L2 blocks that can
//!    be published for each L1 block, preventing the sequencer from censoring forced transactions
//!    by over-producing blocks
//! 2. **Publishing blocks with invalid timestamps** - Ensures that block timestamps are strictly
//!    increasing to maintain temporal ordering
//!
//! ## How it works
//!
//! The rule enforcer operates as a rollup module that implements hooks that are called at the end
//! of each L2 block. It maintains state about:
//! - The maximum number of L2 blocks allowed per L1 block
//! - The current count of L2 blocks for the current L1 block
//! - The last DA (Data Availability) root hash to detect L1 block transitions
//! - The last block timestamp to enforce temporal ordering
//!
//! When a new L2 block is produced, the enforcer:
//! 1. Checks if we've moved to a new L1 block by comparing DA root hashes
//! 2. If still on the same L1 block, increments the counter and verifies it doesn't exceed the limit
//! 3. If on a new L1 block, resets the counter to 1
//! 4. Validates that the new block's timestamp is greater than the previous block's timestamp
//!
//! ## Configuration
//!
//! The module is configured at genesis with:
//! - `authority`: The address authorized to modify the max L2 blocks per L1 setting (typically the sequencer)
//! - `max_l2_blocks_per_l1`: The maximum number of L2 blocks allowed per L1 block
//!
//! ## Authority Management
//!
//! The module supports runtime changes to its configuration through authority-controlled calls:
//! - Changing the authority address
//! - Modifying the maximum L2 blocks per L1 limit
//!
//! Both operations require authorization from the current authority address.

#![warn(clippy::missing_docs_in_private_items)]

mod call;
mod genesis;
mod hooks;
use borsh::{BorshDeserialize, BorshSerialize};
pub use call::*;
pub use genesis::*;

#[cfg(feature = "native")]
mod query;
#[cfg(feature = "native")]
pub use query::*;

#[cfg(all(test, feature = "native"))]
mod tests;

// "Given DA slot hasn't been used for more than N l2 block blocks."
#[cfg(feature = "native")]
use sov_db::ledger_db::LedgerDB; // for rpc
use sov_modules_api::{Address, Context, DaSpec, ModuleInfo, StateValue, WorkingSet};
use sov_state::codec::{BcsCodec, BorshCodec};
use sov_state::storage::StateValueCodec;

/// Internal data structure that stores the rule enforcer's state.
/// This data is persisted in the rollup state and updated after each L2 block.
#[derive(Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
struct RuleEnforcerData {
    /// Maximum number of L2 blocks per L1 slot.
    max_l2_blocks_per_l1: u32,
    /// Last DA slot hash.
    last_da_root_hash: [u8; 32],
    /// How many L2 blocks were published for a specific L1 block.
    counter: u32,
    /// Sequencer's block timestamp
    last_timestamp: u64,
}

/// Codec implementation for serializing/deserializing RuleEnforcerData using Borsh.
impl StateValueCodec<RuleEnforcerData> for BorshCodec {
    type Error = std::io::Error;

    /// Encodes the RuleEnforcerData into bytes using Borsh serialization.
    fn encode_value(&self, value: &RuleEnforcerData) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 32 + 4 + 8);
        BorshSerialize::serialize(value, &mut buf).unwrap();
        buf
    }

    /// Decodes bytes back into RuleEnforcerData using Borsh deserialization.
    fn try_decode_value(&self, bytes: &[u8]) -> Result<RuleEnforcerData, Self::Error> {
        borsh::from_slice(bytes)
    }
}

/// The L2 Block Rule Enforcer module that enforces block production rules.
///
/// This module ensures that:
/// 1. The sequencer doesn't publish more than the configured number of L2 blocks per L1 block
/// 2. Block timestamps are strictly increasing
///
/// Generic parameters:
/// - `C`: The context type that provides sender information and other execution context
/// - `Da`: The data availability specification that defines how blocks are committed to L1
#[derive(ModuleInfo, Clone)]
#[module(rename = "L")]
pub struct L2BlockRuleEnforcer<C: Context, Da: DaSpec> {
    /// Address of the L2BlockRuleEnforcer module.
    #[address]
    address: C::Address,
    /// The main state data for the rule enforcer.
    #[state]
    pub(crate) data: StateValue<RuleEnforcerData, BorshCodec>,
    /// Authority address. Address of the sequencer.
    /// This address is allowed to modify the max L2 blocks per L1.
    #[state]
    pub(crate) authority: StateValue<Address, BorshCodec>,
    /// Phantom state using the da type.
    /// This is used to make sure that the state is generic over the DA type.
    #[allow(dead_code)]
    #[state]
    pub(crate) phantom: StateValue<Da::SlotHash, BcsCodec>,
}

impl<C: Context, Da: DaSpec> sov_modules_api::Module for L2BlockRuleEnforcer<C, Da> {
    type Context = C;

    type Config = L2BlockRuleEnforcerConfig;

    type CallMessage = CallMessage;

    fn call(
        &mut self,
        message: Self::CallMessage,
        context: &Self::Context,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<sov_modules_api::CallResponse, sov_modules_api::L2BlockModuleCallError> {
        match message {
            CallMessage::ChangeAuthority { new_authority } => {
                Ok(self.change_authority(new_authority, context, working_set)?)
            }
            CallMessage::ModifyMaxL2BlocksPerL1 {
                max_l2_blocks_per_l1,
            } => {
                Ok(self.modify_max_l2_blocks_per_l1(max_l2_blocks_per_l1, context, working_set)?)
            }
        }
    }

    fn genesis(&self, config: &Self::Config, working_set: &mut WorkingSet<C::Storage>) {
        self.init_module(config, working_set)
    }
}
