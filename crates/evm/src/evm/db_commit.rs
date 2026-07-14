use std::collections::BTreeMap;

// TODO: right now this is fold_map both in zk and native
// we should check if it increases cycle counts
use alloy_primitives::map::HashMap;
use alloy_primitives::Address;
use revm::state::{Account, AccountInfo};
use revm::DatabaseCommit;
use sov_modules_api::{SpecId, StateMapAccessor};

use super::db::{is_bytecode_cached, EvmDb};
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
                // for backwards compatibility (needed on devnet and testnet only fix the issue post TangeloSelfdestructFix)
                if self.citrea_spec >= SpecId::TangeloSelfdestructFix {
                    // EIP-6780: Account created and destroyed in same TX is fully deleted.
                    // Any cBTC in the contract before selfdestruct is sent to some beneficiary.
                    // Any cBTC sent after selfdestruct is lost (matches Ethereum behavior).
                    let info = DbAccountInfo::default();
                    self.evm.account_set(&address, &info, self.working_set);
                }
                // As we only deal with post-cancun spec, storage couldn't have been
                // set before for a selfdestructed account (it was just created).
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
                // Cached code is already in the offchain cache log, so the read below
                // could only confirm what is there — in the circuit at the price of
                // decoding the whole contract again.
                if !code.is_empty() && !is_bytecode_cached(&new_info.code_hash) {
                    // we don't update code with analyzed code because that would mean we can change jump table
                    // however we want without changing the code hash
                    // that means we can fiddle with tx execution
                    if !self.is_code_stored(&new_info.code_hash) {
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
