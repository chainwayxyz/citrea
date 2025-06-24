//! Genesis configuration and initialization for the L2 Block Rule Enforcer module.
//!
//! This module handles the initial setup of the rule enforcer during chain genesis,
//! setting the initial authority and maximum L2 blocks per L1 configuration.

use serde::{Deserialize, Serialize};
use sov_modules_api::{Address, Context, DaSpec, StateValueAccessor, WorkingSet};

use crate::{L2BlockRuleEnforcer, RuleEnforcerData};

/// Configuration for the L2BlockRuleEnforcer module at genesis.
///
/// This configuration sets the initial parameters for the rule enforcer:
/// - The authority address that can modify settings
/// - The maximum number of L2 blocks allowed per L1 block
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct L2BlockRuleEnforcerConfig {
    /// Authority address. Address of the sequencer.
    /// This address is allowed to modify the max L2 blocks per L1.
    pub(crate) authority: Address,
    /// Maximum number of L2 blocks per L1 slot.
    pub(crate) max_l2_blocks_per_l1: u32,
}

impl<C: Context, Da: DaSpec> L2BlockRuleEnforcer<C, Da> {
    /// Initializes the L2 Block Rule Enforcer module during genesis.
    ///
    /// This method sets up the initial state of the rule enforcer with:
    /// - The authority address from the configuration
    /// - Initial rule enforcer data with zero counters and timestamps
    /// - The configured maximum L2 blocks per L1 limit
    ///
    /// # Arguments
    ///
    /// * `config` - The genesis configuration containing authority and limits
    /// * `working_set` - The working set for state initialization
    ///
    /// # State Initialization
    ///
    /// The method initializes the rule enforcer with:
    /// - `counter`: 0 (no L2 blocks produced yet)
    /// - `max_l2_blocks_per_l1`: from configuration
    /// - `last_timestamp`: 0 (genesis timestamp)
    /// - `last_da_root_hash`: all zeros (no previous DA block)
    pub(crate) fn init_module(
        &self,
        config: &<Self as sov_modules_api::Module>::Config,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        self.authority.set(&config.authority, working_set);

        self.data.set(
            &RuleEnforcerData {
                counter: 0,
                max_l2_blocks_per_l1: config.max_l2_blocks_per_l1,
                last_timestamp: 0,
                last_da_root_hash: [0; 32],
            },
            working_set,
        );
    }
}
