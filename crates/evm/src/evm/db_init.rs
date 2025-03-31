use alloy_primitives::U256;
#[cfg(test)]
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{Address, Bytecode, B256};
use sov_modules_api::StateMapAccessor;

use super::db::EvmDb;
use super::AccountInfo;

/// Initializes database with a predefined account.
pub(crate) trait InitEvmDb {
    fn insert_account_info(&mut self, address: Address, acc: AccountInfo);
    fn insert_code(&mut self, code_hash: B256, code: Bytecode);
    fn insert_storage(&mut self, address: Address, index: U256, value: U256);
}

impl<C: sov_modules_api::Context> InitEvmDb for EvmDb<'_, C> {
    fn insert_account_info(&mut self, sender: Address, info: AccountInfo) {
        self.evm.account_set(&sender, &info, self.working_set);
    }

    fn insert_code(&mut self, code_hash: B256, code: Bytecode) {
        self.evm
            .offchain_code
            .set(&code_hash, &code, &mut self.working_set.offchain_state())
    }

    fn insert_storage(&mut self, address: Address, index: U256, value: U256) {
        let _info = self
            .evm
            .account_info(&address, self.working_set)
            .expect("Account should already be inserted");
        self.evm
            .storage_set(&address, &index, &value, self.working_set);
    }
}

#[cfg(test)]
impl InitEvmDb for CacheDB<EmptyDB> {
    fn insert_account_info(&mut self, sender: Address, acc: AccountInfo) {
        self.insert_account_info(sender, acc.into());
    }

    fn insert_code(&mut self, code_hash: B256, code: Bytecode) {
        self.contracts.insert(code_hash, code);
    }

    fn insert_storage(&mut self, address: Address, index: U256, value: U256) {
        self.insert_account_storage(address, index, value).unwrap();
    }
}
