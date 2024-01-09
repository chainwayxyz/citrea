use reth_primitives::{Account, Address, BlockNumberOrTag, SealedHeader, KECCAK_EMPTY};
use reth_rpc_types::Block;
use sov_modules_api::StateValueAccessor;
use sov_modules_api::StateVecAccessor;
use sov_modules_api::{StateMapAccessor, WorkingSet};

use crate::Evm;
use crate::EvmChainConfig;
use crate::SealedBlock;

impl<C: sov_modules_api::Context> Evm<C> {
    /// Returns the account at the given address.
    pub fn basic_account(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C>,
    ) -> Option<Account> {
        self.accounts.get(address, working_set).map(|acc| Account {
            nonce: acc.info.nonce,
            balance: acc.info.balance,
            bytecode_hash: if acc.info.code_hash == KECCAK_EMPTY {
                None
            } else {
                Some(acc.info.code_hash)
            },
        })
    }

    /// Returns the evm chain config.
    pub fn cfg(&self, working_set: &mut WorkingSet<C>) -> EvmChainConfig {
        self.cfg.get(working_set).expect("EVM config should be set")
    }

    /// Returns the head block.
    pub fn latest_header(&self, working_set: &mut WorkingSet<C>) -> SealedHeader {
        self.latest_sealed_block(working_set).header
    }

    /// Returns the sealed head block.
    pub fn latest_sealed_block(&self, working_set: &mut WorkingSet<C>) -> SealedBlock {
        self.blocks
            .last(&mut working_set.accessory_state())
            .unwrap()
    }

    /// Returns the latest undetailed block.
    pub fn latest_block(&self, working_set: &mut WorkingSet<C>) -> Block {
        self.get_block_by_number(Some(BlockNumberOrTag::Latest), None, working_set)
            .unwrap()
            .unwrap()
            .inner
    }
}
