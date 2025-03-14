use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_modules_core::{AccessoryWorkingSet, Context, Spec, WorkingSet};
use sov_rollup_interface::block::L2Block;
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::spec::SpecId;
pub use sov_rollup_interface::stf::L2BlockError;
use sov_rollup_interface::stf::L2BlockHookError;
use sov_rollup_interface::transaction::Transaction;
use sov_rollup_interface::zk::StorageRootHash;

/// Hooks that execute within the `StateTransitionFunction::apply_blob` function for each processed transaction.
///
/// The arguments consist of expected concretely implemented associated types for the hooks. At
/// runtime, compatible implementations are selected and utilized by the system to construct its
/// setup procedures and define post-execution routines.
pub trait TxHooks {
    type Context: Context;
    type PreArg;
    type PreResult;

    /// Runs just before a transaction is dispatched to an appropriate module.
    fn pre_dispatch_tx_hook(
        &self,
        tx: &Transaction,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
        arg: &Self::PreArg,
        spec_id: SpecId,
    ) -> Result<Self::PreResult, L2BlockHookError>;

    /// Runs after the tx is dispatched to an appropriate module.
    /// IF this hook returns error rollup panics
    fn post_dispatch_tx_hook(
        &self,
        tx: &Transaction,
        ctx: &Self::Context,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
        spec_id: SpecId,
    ) -> Result<(), L2BlockHookError>;
}

/// Hooks that are executed before and after a l2 block is processed.
pub trait ApplyL2BlockHooks<Da: DaSpec> {
    type Context: Context;

    /// Runs at the beginning of apply_l2_block.
    /// If this hook returns Err, batch is not applied
    fn begin_l2_block_hook(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> Result<(), L2BlockHookError>;

    /// Executes at the end of apply_blob and rewards or slashes the sequencer
    /// If this hook returns Err rollup panics
    fn end_l2_block_hook(
        &mut self,
        l2_block_info: HookL2BlockInfo,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> Result<(), L2BlockHookError>;
}

/// Post fork 2 Information about the l2 block block
/// Does not include l1 data
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Eq)]
pub struct HookL2BlockInfo {
    // L2 block height
    pub l2_height: u64,
    /// Previous batch's pre state root
    pub pre_state_root: StorageRootHash,
    /// The current spec
    pub current_spec: SpecId,
    /// Public key of the sequencer
    pub sequencer_pub_key: Vec<u8>,
    /// L1 fee rate
    pub l1_fee_rate: u128,
    /// Timestamp
    pub timestamp: u64,
}

impl HookL2BlockInfo {
    pub fn l2_height(&self) -> u64 {
        self.l2_height
    }

    pub fn pre_state_root(&self) -> StorageRootHash {
        self.pre_state_root
    }

    pub fn current_spec(&self) -> SpecId {
        self.current_spec
    }

    pub fn sequencer_pub_key(&self) -> &[u8] {
        self.sequencer_pub_key.as_slice()
    }

    pub fn l1_fee_rate(&self) -> u128 {
        self.l1_fee_rate
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    #[cfg(feature = "testing")]
    pub fn set_time_stamp(&mut self, timestamp: u64) {
        self.timestamp = timestamp;
    }
}

impl HookL2BlockInfo {
    pub fn new(
        l2_block: &L2Block,
        pre_state_root: StorageRootHash,
        current_spec: SpecId,
        sequencer_pub_key: Vec<u8>,
    ) -> Self {
        Self {
            l2_height: l2_block.height(),
            pre_state_root,
            current_spec,
            sequencer_pub_key,
            l1_fee_rate: l2_block.l1_fee_rate(),
            timestamp: l2_block.timestamp(),
        }
    }
}

/// Hooks that execute during the `StateTransitionFunction::begin_slot` and `end_slot` functions.
pub trait SlotHooks<Da: DaSpec> {
    type Context: Context;

    fn begin_slot_hook(
        &self,
        slot_header: &Da::BlockHeader,
        pre_state_root: &StorageRootHash,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    );

    fn end_slot_hook(&self, working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>);
}

pub trait FinalizeHook<Da: DaSpec> {
    type Context: Context;

    fn finalize_hook(
        &self,
        root_hash: &StorageRootHash,
        accessory_working_set: &mut AccessoryWorkingSet<<Self::Context as Spec>::Storage>,
    );
}
