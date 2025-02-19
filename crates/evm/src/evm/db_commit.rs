use std::collections::BTreeMap;

use alloy_primitives::{Address, U256};
use revm::primitives::{Account, AccountInfo, HashMap, SpecId};
use revm::DatabaseCommit;
use sov_modules_api::{StateMapAccessor, StateVecAccessor};

use super::db::EvmDb;
use super::{AccountInfo as DbAccountInfo, DbAccount};

impl<'a, C: sov_modules_api::Context> DatabaseCommit for EvmDb<'a, C> {
    fn commit(&mut self, changes: HashMap<Address, Account>) {
        // DO NOT REMOVE THIS LINE UNTIL REVM HAS BTREEMAP VERSION. WE MUST ENFORCE THE SAME ORDER.
        let changes = changes.into_iter().collect::<BTreeMap<_, _>>();
        for (address, account) in changes {
            if !account.is_touched() {
                continue;
            }
            let mut new_account_flag = false;

            let prev_info = self
                .evm
                .account_info(&address, self.citrea_spec, self.working_set)
                .unwrap_or_else(|| {
                    new_account_flag = true;
                    DbAccountInfo::default()
                });
            let db_account = DbAccount::new(&address);

            if account.is_selfdestructed() {
                if self.evm_spec.is_enabled_in(SpecId::CANCUN) {
                    // SELFDESTRUCT does not delete any data (including storage keys, code, or the account itself).
                    continue;
                }

                // clear storage

                let keys_to_remove: Vec<U256> = db_account.keys.iter(self.working_set).collect();
                self.evm.storage_delete(
                    &address,
                    &keys_to_remove,
                    self.citrea_spec,
                    self.working_set,
                );
                db_account.keys.clear(self.working_set);

                // Do not clear account.code, because there
                // may exist duplicate contracts with the same code.
                // self.code.delete(...) <- DONT DO THIS

                self.evm
                    .account_delete(&address, self.citrea_spec, self.working_set);
                continue;
            }

            let new_info = account.info;

            if let Some(ref code) = new_info.code {
                if !code.is_empty() {
                    if self.evm_spec.is_enabled_in(SpecId::CANCUN) {
                        // If after Kumquat, just set the offchain code if doesn't already exist
                        // for contracts deployed before, self.code is set and they will be moved
                        // to offchain code next time they are read.
                        //
                        // this if is not &&'ed with the above if, because if we are after Kumquat, we
                        // don't even want to check or set the code in self.code
                        if self
                            .evm
                            .offchain_code
                            .get(&new_info.code_hash, &mut self.working_set.offchain_state())
                            .is_none()
                        {
                            self.evm.offchain_code.set(
                                &new_info.code_hash,
                                code,
                                &mut self.working_set.offchain_state(),
                            );
                        }
                    } else if self
                        .evm
                        .code
                        .get(&new_info.code_hash, self.working_set)
                        .is_none()
                    {
                        // If before Kumquat, set the code in self.code only if it doesn't already exist
                        self.evm
                            .code
                            .set(&new_info.code_hash, code, self.working_set);
                    }
                }
            }

            let storage_slots = account.storage.into_iter().collect::<BTreeMap<_, _>>();
            // insert to StateVec keys must sorted -- or else nodes will have different state roots
            for (key, value) in storage_slots.into_iter() {
                let value = value.present_value();
                // If cancun is enabled there is no need to add the keys because they will not be deleted
                if !self.evm_spec.is_enabled_in(SpecId::CANCUN)
                    && self
                        .evm
                        .storage_get(&address, &key, self.citrea_spec, self.working_set)
                        .is_none()
                {
                    db_account.keys.push(&key, self.working_set);
                }
                self.evm
                    .storage_set(&address, &key, &value, self.citrea_spec, self.working_set);
            }

            if new_account_flag || check_account_info_changed(&prev_info, &new_info) {
                let info = new_info.into();
                self.evm
                    .account_set(&address, &info, self.citrea_spec, self.working_set)
            }
        }
    }
}

fn check_account_info_changed(old: &DbAccountInfo, new: &AccountInfo) -> bool {
    old.balance != new.balance || old.code_hash != Some(new.code_hash) || old.nonce != new.nonce
}
