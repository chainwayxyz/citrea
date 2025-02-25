use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_modules_core::{AccessoryWorkingSet, Context, Spec, WorkingSet};
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::soft_confirmation::L2Block;
use sov_rollup_interface::spec::SpecId;
pub use sov_rollup_interface::stf::SoftConfirmationError;
use sov_rollup_interface::stf::SoftConfirmationHookError;
use sov_rollup_interface::zk::StorageRootHash;

use crate::transaction::Transaction;

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
    ) -> Result<Self::PreResult, SoftConfirmationHookError>;

    /// Runs after the tx is dispatched to an appropriate module.
    /// IF this hook returns error rollup panics
    fn post_dispatch_tx_hook(
        &self,
        tx: &Transaction,
        ctx: &Self::Context,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
        spec_id: SpecId,
    ) -> Result<(), SoftConfirmationHookError>;
}

/// Hooks that are executed before and after a soft confirmation is processed.
pub trait ApplySoftConfirmationHooks<Da: DaSpec> {
    type Context: Context;

    /// Runs at the beginning of apply_soft_confirmation.
    /// If this hook returns Err, batch is not applied
    fn begin_soft_confirmation_hook(
        &mut self,
        soft_confirmation_info: &HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> Result<(), SoftConfirmationHookError>;

    /// Executes at the end of apply_blob and rewards or slashes the sequencer
    /// If this hook returns Err rollup panics
    fn end_soft_confirmation_hook(
        &mut self,
        soft_confirmation_info: HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> Result<(), SoftConfirmationHookError>;
}

/// Pre fork2 Information about the soft confirmation block
/// Does not include txs because txs can be appended by the sequencer
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Eq)]
pub struct HookSoftConfirmationInfoV1 {
    /// L2 block height
    pub l2_height: u64,
    /// DA block this soft confirmation was given for
    pub da_slot_height: u64,
    /// DA block hash
    pub da_slot_hash: [u8; 32],
    /// DA block transactions commitment
    pub da_slot_txs_commitment: [u8; 32],
    /// Previous batch's pre state root
    pub pre_state_root: StorageRootHash,
    /// The current spec
    pub current_spec: SpecId,
    /// Public key of the sequencer
    pub pub_key: Vec<u8>,
    /// Deposit data from the L1 chain
    pub deposit_data: Vec<Vec<u8>>,
    /// L1 fee rate
    pub l1_fee_rate: u128,
    /// Timestamp
    pub timestamp: u64,
}

/// Post fork 2 Information about the soft confirmation block
/// Does not include l1 data
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Eq)]
pub struct HookSoftConfirmationInfoV2 {
    // L2 block height
    pub l2_height: u64,
    /// Previous batch's pre state root
    pub pre_state_root: StorageRootHash,
    /// The current spec
    pub current_spec: SpecId,
    /// Public key of the sequencer
    pub pub_key: Vec<u8>,
    /// L1 fee rate
    pub l1_fee_rate: u128,
    /// Timestamp
    pub timestamp: u64,
}

#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Eq)]
pub enum HookSoftConfirmationInfo {
    V1(HookSoftConfirmationInfoV1),
    V2(HookSoftConfirmationInfoV2),
}

pub enum HookSoftConfirmationInfoVersion {
    V1,
    V2,
}

impl HookSoftConfirmationInfo {
    pub fn version(&self) -> HookSoftConfirmationInfoVersion {
        match self {
            HookSoftConfirmationInfo::V1(_) => HookSoftConfirmationInfoVersion::V1,
            HookSoftConfirmationInfo::V2(_) => HookSoftConfirmationInfoVersion::V2,
        }
    }

    pub fn l2_height(&self) -> u64 {
        match self {
            HookSoftConfirmationInfo::V1(info) => info.l2_height,
            HookSoftConfirmationInfo::V2(info) => info.l2_height,
        }
    }

    pub fn pre_state_root(&self) -> StorageRootHash {
        match self {
            HookSoftConfirmationInfo::V1(info) => info.pre_state_root,
            HookSoftConfirmationInfo::V2(info) => info.pre_state_root,
        }
    }

    pub fn current_spec(&self) -> SpecId {
        match self {
            HookSoftConfirmationInfo::V1(info) => info.current_spec,
            HookSoftConfirmationInfo::V2(info) => info.current_spec,
        }
    }

    pub fn sequencer_pub_key(&self) -> &[u8] {
        match self {
            HookSoftConfirmationInfo::V1(info) => info.pub_key.as_ref(),
            HookSoftConfirmationInfo::V2(info) => info.pub_key.as_ref(),
        }
    }

    pub fn deposit_data(&self) -> Vec<Vec<u8>> {
        match self {
            HookSoftConfirmationInfo::V1(info) => info.deposit_data.clone(),
            HookSoftConfirmationInfo::V2(_) => panic!("V2 does not have deposit data"),
        }
    }

    pub fn l1_fee_rate(&self) -> u128 {
        match self {
            HookSoftConfirmationInfo::V1(info) => info.l1_fee_rate,
            HookSoftConfirmationInfo::V2(info) => info.l1_fee_rate,
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            HookSoftConfirmationInfo::V1(info) => info.timestamp,
            HookSoftConfirmationInfo::V2(info) => info.timestamp,
        }
    }

    pub fn da_slot_hash(&self) -> Option<[u8; 32]> {
        match self {
            HookSoftConfirmationInfo::V1(info) => Some(info.da_slot_hash),
            HookSoftConfirmationInfo::V2(_) => None,
        }
    }

    pub fn da_slot_txs_commitment(&self) -> Option<[u8; 32]> {
        match self {
            HookSoftConfirmationInfo::V1(info) => Some(info.da_slot_txs_commitment),
            HookSoftConfirmationInfo::V2(_) => None,
        }
    }

    pub fn da_slot_height(&self) -> Option<u64> {
        match self {
            HookSoftConfirmationInfo::V1(info) => Some(info.da_slot_height),
            HookSoftConfirmationInfo::V2(_) => None,
        }
    }

    #[cfg(feature = "testing")]
    pub fn set_da_slot_hash(&mut self, da_slot_hash: [u8; 32]) {
        if let HookSoftConfirmationInfo::V1(info) = self {
            info.da_slot_hash = da_slot_hash
        }
    }

    #[cfg(feature = "testing")]
    pub fn set_time_stamp(&mut self, timestamp: u64) {
        match self {
            HookSoftConfirmationInfo::V1(info) => info.timestamp = timestamp,
            HookSoftConfirmationInfo::V2(info) => info.timestamp = timestamp,
        }
    }
}

impl HookSoftConfirmationInfo {
    pub fn new<Tx: Clone + BorshSerialize>(
        l2_block: &L2Block<Tx>,
        pre_state_root: StorageRootHash,
        current_spec: SpecId,
    ) -> Self {
        if current_spec >= SpecId::Fork2 {
            return HookSoftConfirmationInfo::V2(HookSoftConfirmationInfoV2 {
                l2_height: l2_block.l2_height(),
                pre_state_root,
                current_spec,
                pub_key: l2_block.sequencer_pub_key().to_vec(),
                l1_fee_rate: l2_block.l1_fee_rate(),
                timestamp: l2_block.timestamp(),
            });
        }
        HookSoftConfirmationInfo::V1(HookSoftConfirmationInfoV1 {
            l2_height: l2_block.l2_height(),
            da_slot_hash: l2_block.da_slot_hash(),
            da_slot_height: l2_block.da_slot_height(),
            da_slot_txs_commitment: l2_block.da_slot_txs_commitment(),
            pre_state_root,
            current_spec,
            pub_key: l2_block.sequencer_pub_key().to_vec(),
            deposit_data: l2_block.deposit_data().to_vec(),
            l1_fee_rate: l2_block.l1_fee_rate(),
            timestamp: l2_block.timestamp(),
        })
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
