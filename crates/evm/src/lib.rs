#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
mod call;
mod evm;
mod genesis;
mod hooks;
#[cfg(feature = "native")]
mod provider_functions;

pub use call::*;
pub use evm::*;
pub use genesis::*;
pub use system_events::SYSTEM_SIGNER;

#[cfg(feature = "native")]
mod rpc_helpers;
#[cfg(feature = "native")]
pub use error::rpc::*;
#[cfg(feature = "native")]
pub use rpc_helpers::*;
#[cfg(feature = "native")]
mod query;
#[cfg(feature = "native")]
pub use query::*;
#[cfg(feature = "native")]
mod signer;
#[cfg(feature = "native")]
pub use signer::DevSigner;
#[cfg(feature = "native")]
pub mod smart_contracts;

#[cfg(all(test, feature = "native"))]
mod tests;

use alloy_primitives::{Address, TxHash, B256};
use evm::db::EvmDb;
pub use revm::primitives::SpecId;
use revm::primitives::U256;
#[cfg(feature = "native")]
use sov_modules_api::{AccessoryWorkingSet, StateVecAccessor};
use sov_modules_api::{Error, ModuleInfo, WorkingSet};
use sov_state::codec::BcsCodec;

#[cfg(feature = "native")]
use crate::evm::primitive_types::SealedBlock;
use crate::evm::primitive_types::{Block, BlockEnv, Receipt, TransactionSignedAndRecovered};
use crate::evm::system_events::SystemEvent;
pub use crate::EvmConfig;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
/// Pending EVM transaction
pub struct PendingTransaction {
    pub(crate) transaction: TransactionSignedAndRecovered,
    pub(crate) receipt: Receipt,
}

impl PendingTransaction {
    /// Returns the transaction's hash
    pub fn hash(&self) -> TxHash {
        self.transaction.signed_transaction.hash
    }

    /// Returns the cumulative gas used for this transaction
    pub fn cumulative_gas_used(&self) -> u64 {
        self.receipt.receipt.cumulative_gas_used
    }
}

/// The citrea-evm module provides compatibility with the EVM.
// #[cfg_attr(feature = "native", derive(sov_modules_api::ModuleCallJsonSchema))]
#[derive(ModuleInfo, Clone)]
pub struct Evm<C: sov_modules_api::Context> {
    /// The address of the evm module.
    #[address]
    pub(crate) address: C::Address,

    /// Mapping from account address to account state.
    #[state(rename = "a")]
    pub(crate) accounts: sov_modules_api::StateMap<Address, AccountInfo, BcsCodec>,

    /// Mapping from code hash to code. Used for lazy-loading code into a contract account.
    #[state(rename = "c")]
    pub(crate) code:
        sov_modules_api::StateMap<alloy_primitives::B256, revm::primitives::Bytecode, BcsCodec>,

    /// Chain configuration. This field is set in genesis.
    #[state]
    pub(crate) cfg: sov_modules_api::StateValue<EvmChainConfig, BcsCodec>,

    /// Block environment used by the evm. This field is set in `begin_slot_hook`.
    #[memory]
    pub(crate) block_env: BlockEnv,

    /// Transactions that will be added to the current block.
    /// Valid transactions are added to the vec on every call message.
    #[memory]
    pub(crate) pending_transactions: Vec<PendingTransaction>,

    /// Head of the chain. The new head is set in `end_slot_hook` but without the inclusion of the `state_root` field.
    /// The `state_root` is added in `begin_slot_hook` of the next block because its calculation occurs after the `end_slot_hook`.
    #[state]
    pub(crate) head: sov_modules_api::StateValue<Block, BcsCodec>,

    /// Last seen L1 block hash.
    #[state(rename = "l")]
    pub(crate) last_l1_hash: sov_modules_api::StateValue<B256, BcsCodec>,

    /// Last 256 block hashes. Latest blockhash is populated in `begin_slot_hook`.
    /// Removes the oldest blockhash in `finalize_hook`
    /// Used by the EVM to calculate the `blockhash` opcode.
    #[state(rename = "h")]
    pub(crate) latest_block_hashes: sov_modules_api::StateMap<U256, B256, BcsCodec>,

    /// Native pending transactions. Used to store transactions that are not yet included in the block.
    /// We use this in the sequencer to see which txs did not fail
    #[cfg(feature = "native")]
    #[state]
    pub(crate) native_pending_transactions:
        sov_modules_api::AccessoryStateVec<PendingTransaction, BcsCodec>,

    /// Transaction's hash that failed to pay the L1 fee.
    /// Used to prevent DOS attacks.
    /// The vector is cleared in `finalize_hook`.
    #[cfg(feature = "native")]
    #[state]
    pub(crate) l1_fee_failed_txs: sov_modules_api::AccessoryStateVec<TxHash, BcsCodec>,

    /// Used only by the RPC: This represents the head of the chain and is set in two distinct stages:
    /// 1. `end_slot_hook`: the pending head is populated with data from pending_transactions.
    /// 2. `finalize_hook` the `root_hash` is populated.
    /// Since this value is not authenticated, it can be modified in the `finalize_hook` with the correct `state_root`.
    #[cfg(feature = "native")]
    #[state]
    pub(crate) pending_head: sov_modules_api::AccessoryStateValue<Block, BcsCodec>,

    /// Used only by the RPC: The vec is extended with `pending_head` in `finalize_hook`.
    #[cfg(feature = "native")]
    #[state]
    pub(crate) blocks: sov_modules_api::AccessoryStateVec<SealedBlock, BcsCodec>,

    /// Used only by the RPC: block_hash => block_number mapping,
    #[cfg(feature = "native")]
    #[state]
    pub(crate) block_hashes:
        sov_modules_api::AccessoryStateMap<reth_primitives::B256, u64, BcsCodec>,

    /// Used only by the RPC: List of processed transactions.
    #[cfg(feature = "native")]
    #[state]
    pub(crate) transactions:
        sov_modules_api::AccessoryStateVec<TransactionSignedAndRecovered, BcsCodec>,

    /// Used only by the RPC: transaction_hash => transaction_index mapping.
    #[cfg(feature = "native")]
    #[state]
    pub(crate) transaction_hashes:
        sov_modules_api::AccessoryStateMap<reth_primitives::B256, u64, BcsCodec>,

    /// Used only by the RPC: Receipts.
    #[cfg(feature = "native")]
    #[state]
    pub(crate) receipts: sov_modules_api::AccessoryStateVec<Receipt, BcsCodec>,
}

impl<C: sov_modules_api::Context> sov_modules_api::Module for Evm<C> {
    type Context = C;

    type Config = EvmConfig;

    type CallMessage = call::CallMessage;

    type Event = ();

    fn genesis(&self, config: &Self::Config, working_set: &mut WorkingSet<C>) -> Result<(), Error> {
        Ok(self.init_module(config, working_set)?)
    }

    fn call(
        &mut self,
        msg: Self::CallMessage,
        context: &Self::Context,
        working_set: &mut WorkingSet<C>,
    ) -> Result<sov_modules_api::CallResponse, Error> {
        Ok(self.execute_call(msg.txs, context, working_set)?)
    }
}

impl<C: sov_modules_api::Context> Evm<C> {
    pub(crate) fn get_db<'a>(&self, working_set: &'a mut WorkingSet<C>) -> EvmDb<'a, C> {
        EvmDb::new(
            self.accounts.clone(),
            self.code.clone(),
            self.latest_block_hashes.clone(),
            working_set,
        )
    }

    /// Returns transaction hashes that failed to pay the L1 fee.
    #[cfg(feature = "native")]
    pub fn get_l1_fee_failed_txs(
        &self,
        accessory_working_set: &mut AccessoryWorkingSet<C>,
    ) -> Vec<TxHash> {
        self.l1_fee_failed_txs.iter(accessory_working_set).collect()
    }

    /// Returns the list of pending EVM transactions
    #[cfg(feature = "native")]
    pub fn get_last_pending_transaction(
        &self,
        accessory_working_set: &mut WorkingSet<C>,
    ) -> Option<PendingTransaction> {
        self.native_pending_transactions
            .last(&mut accessory_working_set.accessory_state())
    }
}
