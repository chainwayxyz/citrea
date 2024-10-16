use alloy_primitives::Address;
use reth_primitives::{Account, SealedHeader};
use sov_modules_api::{StateMapAccessor, StateVecAccessor, WorkingSet};

use crate::Evm;

impl<C: sov_modules_api::Context> Evm<C> {
    /// Returns the account at the given address.
    pub fn basic_account(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C>,
    ) -> Option<Account> {
        Some(
            self.accounts
                .get(address, working_set)
                .unwrap_or_default()
                .into(),
        )
    }

    /// Returns the sealed head block.
    pub fn last_sealed_header(&self, working_set: &mut WorkingSet<C>) -> SealedHeader {
        self.blocks
            .last(&mut working_set.accessory_state())
            .unwrap()
            .header
    }
}
