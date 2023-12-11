#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
mod call;
mod evm;
mod genesis;
mod hooks;
mod rpc_helpers;
pub use call::*;
pub use error::rpc::*;
pub use evm::*;
pub use genesis::*;
pub use hooks::*;
pub use rpc_helpers::*;
#[cfg(feature = "native")]
mod query;
#[cfg(feature = "native")]
pub use query::*;
mod signer;
pub use signer::DevSigner;
#[cfg(feature = "smart_contracts")]
mod smart_contracts;
#[cfg(feature = "smart_contracts")]
pub use smart_contracts::{
    BlockHashContract, LogsContract, SelfDestructorContract, SimpleStorageContract, TestContract,
};

#[cfg(test)]
mod tests;

use evm::db::EvmDb;
use evm::DbAccount;
use reth_primitives::{Address, H256};
pub use revm::primitives::SpecId;
use revm::primitives::U256;
use serde;
use sov_modules_api::{Error, ModuleInfo, WorkingSet};
use sov_state::codec::BcsCodec;

use crate::evm::primitive_types::{
    Block, BlockEnv, Receipt, SealedBlock, TransactionSignedAndRecovered,
};
pub use crate::EvmConfig;

// Gas per transaction not creating a contract.
pub(crate) const MIN_TRANSACTION_GAS: u64 = 21_000u64;
pub(crate) const MIN_CREATE_GAS: u64 = 53_000u64;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingTransaction {
    pub(crate) transaction: TransactionSignedAndRecovered,
    pub(crate) receipt: Receipt,
}

/// The sov-evm module provides compatibility with the EVM.
#[allow(dead_code)]
// #[cfg_attr(feature = "native", derive(sov_modules_api::ModuleCallJsonSchema))]
#[derive(ModuleInfo, Clone)]
pub struct Evm<C: sov_modules_api::Context> {
    /// The address of the evm module.
    #[address]
    pub(crate) address: C::Address,

    /// Mapping from account address to account state.
    #[state]
    pub(crate) accounts: sov_modules_api::StateMap<Address, DbAccount, BcsCodec>,

    /// Mapping from code hash to code. Used for lazy-loading code into a contract account.
    #[state]
    pub(crate) code:
        sov_modules_api::StateMap<reth_primitives::H256, reth_primitives::Bytes, BcsCodec>,

    /// Chain configuration. This field is set in genesis.
    #[state]
    pub(crate) cfg: sov_modules_api::StateValue<EvmChainConfig, BcsCodec>,

    /// Block environment used by the evm. This field is set in `begin_slot_hook`.
    #[state]
    pub(crate) block_env: sov_modules_api::StateValue<BlockEnv, BcsCodec>,

    /// Transactions that will be added to the current block.
    /// A valid transaction is added to the vec on every call message.
    #[state]
    pub(crate) pending_transactions: sov_modules_api::StateVec<PendingTransaction, BcsCodec>,

    /// Head of the chain. The new head is set in `end_slot_hook` but without the inclusion of the `state_root` field.
    /// The `state_root` is added in `begin_slot_hook` of the next block because its calculation occurs after the `end_slot_hook`.
    #[state]
    pub(crate) head: sov_modules_api::StateValue<Block, BcsCodec>,

    /// Last 256 block hashes. Latest blockhash is populated in `begin_slot_hook`.
    /// Removes the oldest blockhash in `finalize_hook`
    /// Used by the EVM to calculate the `blockhash` opcode.
    #[state]
    pub(crate) latest_block_hashes: sov_modules_api::StateMap<U256, H256, BcsCodec>,

    /// Used only by the RPC: This represents the head of the chain and is set in two distinct stages:
    /// 1. `end_slot_hook`: the pending head is populated with data from pending_transactions.
    /// 2. `finalize_hook` the `root_hash` is populated.
    /// Since this value is not authenticated, it can be modified in the `finalize_hook` with the correct `state_root`.
    #[state]
    pub(crate) pending_head: sov_modules_api::AccessoryStateValue<Block, BcsCodec>,

    /// Used only by the RPC: The vec is extended with `pending_head` in `finalize_hook`.
    #[state]
    pub(crate) blocks: sov_modules_api::AccessoryStateVec<SealedBlock, BcsCodec>,

    /// Used only by the RPC: block_hash => block_number mapping,
    #[state]
    pub(crate) block_hashes:
        sov_modules_api::AccessoryStateMap<reth_primitives::H256, u64, BcsCodec>,

    /// Used only by the RPC: List of processed transactions.
    #[state]
    pub(crate) transactions:
        sov_modules_api::AccessoryStateVec<TransactionSignedAndRecovered, BcsCodec>,

    /// Used only by the RPC: transaction_hash => transaction_index mapping.
    #[state]
    pub(crate) transaction_hashes:
        sov_modules_api::AccessoryStateMap<reth_primitives::H256, u64, BcsCodec>,

    /// Used only by the RPC: Receipts.
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
        &self,
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
}
