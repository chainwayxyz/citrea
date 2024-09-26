use std::collections::BTreeMap;

use alloy_primitives::{Address, U256};
use revm::primitives::{Account, AccountInfo, HashMap};
use revm::DatabaseCommit;
use sov_modules_api::{StateMapAccessor, StateVecAccessor};

use super::db::EvmDb;
use super::{AccountInfo as DbAccountInfo, DbAccount};

impl<'a, C: sov_modules_api::Context> DatabaseCommit for EvmDb<'a, C> {
    fn commit(&mut self, changes: HashMap<Address, Account>) {
        let changes = changes.into_iter().collect::<BTreeMap<_, _>>();

        for (address, account) in changes {
            if !account.is_touched() {
                continue;
            }
            let mut new_account_flag = false;

            let info = self
                .accounts
                .get(&address, self.working_set)
                .unwrap_or_else(|| {
                    new_account_flag = true;
                    DbAccountInfo::default()
                });
            let db_account = DbAccount::new(address);

            // https://github.com/Sovereign-Labs/sovereign-sdk/issues/425
            if account.is_selfdestructed() {
                // TODO find mroe efficient way to clear storage
                // https://github.com/chainwayxyz/rollup-modules/issues/4
                // clear storage

                let keys_to_remove: Vec<U256> = db_account.keys.iter(self.working_set).collect();
                for key in keys_to_remove {
                    db_account.storage.delete(&key, self.working_set);
                }
                db_account.keys.clear(self.working_set);

                // Do not clear account.code, because there
                // may exist duplicate contracts with the same code.
                // self.code.delete(...) <- DONT DO THIS

                self.accounts.delete(&address, self.working_set);
                continue;
            }

            let account_info = account.info;

            if let Some(ref code) = account_info.code {
                if !code.is_empty() {
                    let exists_in_db = self
                        .code
                        .get(&account_info.code_hash, self.working_set)
                        .is_some();
                    if !exists_in_db {
                        self.code
                            .set(&account_info.code_hash, code, self.working_set);
                    }
                }
            }

            let storage_slots = account.storage.into_iter().collect::<BTreeMap<_, _>>();
            // insert to StateVec keys must sorted -- or else nodes will have different state roots
            for (key, value) in storage_slots.into_iter() {
                let value = value.present_value();
                if db_account.storage.get(&key, self.working_set).is_none() {
                    db_account.keys.push(&key, self.working_set);
                }
                db_account.storage.set(&key, &value, self.working_set);
            }

            if new_account_flag || check_account_info_changed(&info, &account_info) {
                let info = account_info.into();
                self.accounts.set(&address, &info, self.working_set)
            }
        }
    }
}

fn check_account_info_changed(old: &DbAccountInfo, new: &AccountInfo) -> bool {
    old.balance != new.balance || old.code_hash != Some(new.code_hash) || old.nonce != new.nonce
}
