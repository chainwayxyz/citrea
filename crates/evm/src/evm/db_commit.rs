use std::collections::BTreeMap;

// TODO: right now this is fold_map both in zk and native
// we should check if it increases cycle counts
use alloy_primitives::map::HashMap;
use alloy_primitives::Address;
use revm::state::{Account, AccountInfo};
use revm::DatabaseCommit;
use sov_modules_api::{SpecId, StateMapAccessor};

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
                if self.citrea_spec >= SpecId::Pomelo {
                    // EIP-6780: revm only marks an account as selfdestructed when it was also
                    // created in this transaction. A prefunded address already has an index
                    // and is cleared in place instead.
                    //
                    // Any cBTC in the contract before selfdestruct is sent to some beneficiary.
                    // Any cBTC sent after selfdestruct is lost (matches Ethereum behavior).
                    self.evm.account_clear_if_exists(&address, self.working_set);
                } else if self.citrea_spec >= SpecId::TangeloSelfdestructFix {
                    // Preserve the historical tombstone allocation before Pomelo.
                    let info = DbAccountInfo::default();
                    self.evm.account_set(&address, &info, self.working_set);
                }
                // As we only deal with post-cancun spec, storage couldn't have been
                // set before for a selfdestructed account (it was just created).
                continue;
            }

            let prev_info = self.evm.account_info(&address, self.working_set);

            let new_info = account.info;

            if let Some(ref code) = new_info.code {
                // Only store code an account did not already have. Probing `offchain_code` for
                // presence instead would be a read of unauthenticated state -- in the circuit its
                // answer is a raw witness hint -- and it would seed the offchain cache with that
                // answer, so the later verified read in `code_by_hash` would be served from cache
                // and skip verification entirely. `prev_info` comes from the JMT, so comparing
                // against it decides the same question without reading offchain state at all.
                //
                // The value written here is always canonical: revm derives it in-circuit, either
                // from the deploy output or as an EIP-7702 designator. That is what makes it safe
                // to write over an existing entry when the same code is deployed twice.
                if !code.is_empty()
                    && prev_info.as_ref().and_then(|info| info.code_hash)
                        != Some(new_info.code_hash)
                {
                    self.evm.offchain_code.set(
                        &new_info.code_hash,
                        code,
                        &mut self.working_set.offchain_state(),
                    );
                }
            }

            let only_commit_changed_storage = self.citrea_spec >= SpecId::Pomelo;
            let storage_slots = account
                .storage
                .into_iter()
                .filter(|(_, value)| !only_commit_changed_storage || value.is_changed())
                .collect::<BTreeMap<_, _>>();

            // insert to StateVec keys must sorted -- or else nodes will have different state roots
            for (key, value) in storage_slots.into_iter() {
                let value = value.present_value();

                self.evm
                    .storage_set(&address, &key, &value, self.working_set);
            }

            let is_eip161_fork_fix_enabled = self.citrea_spec >= SpecId::Pomelo;
            let should_skip_empty_account_creation =
                is_eip161_fork_fix_enabled && prev_info.is_none() && new_info.is_empty();

            if !should_skip_empty_account_creation
                && prev_info
                    .as_ref()
                    .is_none_or(|prev_info| check_account_info_changed(prev_info, &new_info))
            {
                let info = new_info.into();
                self.evm.account_set(&address, &info, self.working_set)
            }
        }
    }
}

fn check_account_info_changed(old: &DbAccountInfo, new: &AccountInfo) -> bool {
    old.balance != new.balance || old.code_hash != Some(new.code_hash) || old.nonce != new.nonce
}
