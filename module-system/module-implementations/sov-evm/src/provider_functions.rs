use reth_primitives::{Account, Address, KECCAK_EMPTY};
use sov_modules_api::{StateMapAccessor, WorkingSet};

use crate::Evm;

impl<C: sov_modules_api::Context> Evm<C> {
    /// Returns the account at the given address.
    pub fn basic_account(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C>,
    ) -> Option<Account> {
        self.accounts.get(address, working_set).map(|acc| Account {
            nonce: acc.info.nonce,
            balance: acc.info.balance,
            bytecode_hash: if acc.info.code_hash == KECCAK_EMPTY {
                None
            } else {
                Some(acc.info.code_hash)
            },
        })
    }
}
