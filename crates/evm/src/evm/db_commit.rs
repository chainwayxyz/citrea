use std::collections::BTreeMap;

use alloy_primitives::Address;
use revm::primitives::{Account, AccountInfo, HashMap};
use revm::DatabaseCommit;
use sov_modules_api::StateMapAccessor;

use super::db::EvmDb;
use super::AccountInfo as DbAccountInfo;

impl<C: sov_modules_api::Context> DatabaseCommit for EvmDb<'_, C> {
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
                    // we don't update code with analyzed code because that would mean we can change jump table
                    // however we want without changing the code hash
                    // that means we can fiddle with tx execution
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
