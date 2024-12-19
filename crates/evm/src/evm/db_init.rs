use alloy_primitives::U256;
#[cfg(test)]
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{Address, Bytecode, SpecId, B256};
use sov_modules_api::StateMapAccessor;

use super::db::EvmDb;
use super::{AccountInfo, DbAccount};

/// Initializes database with a predefined account.
pub(crate) trait InitEvmDb {
    fn insert_account_info(&mut self, address: Address, acc: AccountInfo);
    fn insert_code(&mut self, code_hash: B256, code: Bytecode);
    fn insert_storage(&mut self, address: Address, index: U256, value: U256);
}

impl<'a, C: sov_modules_api::Context> InitEvmDb for EvmDb<'a, C> {
    fn insert_account_info(&mut self, sender: Address, info: AccountInfo) {
        self.accounts.set(&sender, &info, self.working_set);
    }

    fn insert_code(&mut self, code_hash: B256, code: Bytecode) {
        if self.current_spec.is_enabled_in(SpecId::CANCUN) {
            self.offchain_code
                .set(&code_hash, &code, &mut self.working_set.offchain_state())
        } else {
            self.code.set(&code_hash, &code, self.working_set)
        }
    }

    fn insert_storage(&mut self, address: Address, index: U256, value: U256) {
        let _info = self
            .accounts
            .get(&address, self.working_set)
            .expect("Account should already be inserted");
        let db_account = DbAccount::new(address);
        db_account.storage.set(&index, &value, self.working_set);
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
