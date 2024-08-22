use reth_primitives::{Account, Address, SealedHeader, KECCAK_EMPTY};
use sov_modules_api::{StateMapAccessor, StateValueAccessor, StateVecAccessor, WorkingSet};

use crate::{DbAccount, Evm};

impl<C: sov_modules_api::Context> Evm<C> {
    /// Returns the account at the given address.
    pub fn basic_account(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C>,
    ) -> Option<Account> {
        let account = self
            .accounts
            .get(address, working_set)
            .unwrap_or(DbAccount::new(self.accounts.prefix(), *address));

        let code_hash = match account.code_hash.get(working_set) {
            Some(code_hash) => {
                if code_hash == KECCAK_EMPTY {
                    None
                } else {
                    Some(code_hash)
                }
            }
            None => None,
        };
        Some(Account {
            nonce: account.nonce.get(working_set).unwrap_or_default(),
            balance: account.balance.get(working_set).unwrap_or_default(),
            bytecode_hash: code_hash,
        })
    }

    /// Returns the sealed head block.
    pub fn last_sealed_header(&self, working_set: &mut WorkingSet<C>) -> SealedHeader {
        self.blocks
            .last(&mut working_set.accessory_state())
            .unwrap()
            .header
    }
}
