use std::collections::BTreeMap;

use alloy_primitives::Address;
use revm::primitives::{Account, AccountInfo, HashMap};
use revm::DatabaseCommit;
use sov_modules_api::StateMapAccessor;

use super::db::EvmDb;
use super::AccountInfo as DbAccountInfo;

impl<'a, C: sov_modules_api::Context> DatabaseCommit for EvmDb<'a, C> {
    fn commit(&mut self, changes: HashMap<Address, Account>) {
        // DO NOT REMOVE THIS LINE UNTIL REVM HAS BTREEMAP VERSION. WE MUST ENFORCE THE SAME ORDER.
        let changes = changes.into_iter().collect::<BTreeMap<_, _>>();
        for (address, account) in changes {
            if !account.is_touched() {
                continue;
            }

            if account.is_selfdestructed() {
                continue;
            }

            let mut new_account_flag = false;

            let prev_info = self
                .evm
                .account_info(&address, self.working_set)
                .unwrap_or_else(|| {
                    new_account_flag = true;
                    DbAccountInfo::default()
                });

            let new_info = account.info;

            if let Some(ref code) = new_info.code {
                if !code.is_empty() {
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
                }
            }

            let storage_slots = account.storage.into_iter().collect::<BTreeMap<_, _>>();
            // insert to StateVec keys must sorted -- or else nodes will have different state roots
            for (key, value) in storage_slots.into_iter() {
                let value = value.present_value();

                self.evm
                    .storage_set(&address, &key, &value, self.working_set);
            }

            if new_account_flag || check_account_info_changed(&prev_info, &new_info) {
                let info = new_info.into();
                self.evm.account_set(&address, &info, self.working_set)
            }
        }
    }
}

fn check_account_info_changed(old: &DbAccountInfo, new: &AccountInfo) -> bool {
    old.balance != new.balance || old.code_hash != Some(new.code_hash) || old.nonce != new.nonce
}
