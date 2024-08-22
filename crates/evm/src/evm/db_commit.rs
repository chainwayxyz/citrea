use std::collections::BTreeMap;

use reth_primitives::{KECCAK_EMPTY, U256};
use revm::primitives::{Account, Address, HashMap};
use revm::DatabaseCommit;
use sov_modules_api::{StateMapAccessor, StateValueAccessor, StateVecAccessor};

use super::db::EvmDb;
use super::DbAccount;

impl<'a, C: sov_modules_api::Context> DatabaseCommit for EvmDb<'a, C> {
    fn commit(&mut self, changes: HashMap<Address, Account>) {
        let changes = changes.into_iter().collect::<BTreeMap<_, _>>();

        for (address, account) in changes {
            if !account.is_touched() {
                continue;
            }
            let accounts_prefix = self.accounts.prefix();

            let db_account = self
                .accounts
                .get(&address, self.working_set)
                .unwrap_or_else(|| {
                    let db_account = DbAccount::new(accounts_prefix, address);
                    // If it is a new account set it here
                    db_account.balance.set(&U256::from(0), self.working_set);
                    db_account.nonce.set(&0, self.working_set);
                    db_account.code_hash.set(&KECCAK_EMPTY, self.working_set);
                    self.accounts.set(&address, &db_account, self.working_set);

                    db_account
                });

            // https://github.com/Sovereign-Labs/sovereign-sdk/issues/425
            if account.is_selfdestructed() {
                db_account.balance.set(&U256::from(0), self.working_set);
                db_account.nonce.set(&0, self.working_set);
                db_account.code_hash.set(&KECCAK_EMPTY, self.working_set);
                // TODO find mroe efficient way to clear storage
                // https://github.com/chainwayxyz/rollup-modules/issues/4
                // clear storage

                let keys_to_remove: Vec<U256> = db_account.keys.iter(self.working_set).collect();
                for key in keys_to_remove {
                    db_account.storage.delete(&key, self.working_set);
                }
                db_account.keys.clear(self.working_set);
                self.accounts.set(&address, &db_account, self.working_set);
                continue;
            }

            let account_info = account.info;

            if let Some(ref code) = account_info.code {
                if !code.is_empty() {
                    // TODO: would be good to have a contains_key method on the StateMap that would be optimized, so we can check the hash before storing the code
                    self.code
                        .set(&account_info.code_hash, code, self.working_set);
                }
            }

            if db_account.balance.get(self.working_set).unwrap_or_default() != account_info.balance
            {
                db_account
                    .balance
                    .set(&account_info.balance, self.working_set);
            }

            if db_account
                .code_hash
                .get(self.working_set)
                .unwrap_or_default()
                != account_info.code_hash
            {
                db_account
                    .code_hash
                    .set(&account_info.code_hash, self.working_set);
            }

            if db_account.nonce.get(self.working_set).unwrap_or_default() != account_info.nonce {
                db_account.nonce.set(&account_info.nonce, self.working_set);
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
        }
    }
}
