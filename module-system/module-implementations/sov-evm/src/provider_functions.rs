use reth_primitives::{Account, Address, SealedHeader};
use sov_modules_api::StateValueAccessor;
use sov_modules_api::StateVecAccessor;
use sov_modules_api::{StateMapAccessor, WorkingSet};

use crate::EvmChainConfig;
use crate::{DbAccount, Evm};

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
                .unwrap_or(DbAccount::new_with_info(
                    self.accounts.prefix(),
                    *address,
                    Default::default(),
                ))
                .info
                .into(),
        )
    }

    /// Returns the evm chain config.
    pub fn get_config(&self, working_set: &mut WorkingSet<C>) -> EvmChainConfig {
        self.cfg.get(working_set).expect("EVM config should be set")
    }

    /// Returns the sealed head block.
    pub fn last_sealed_header(&self, working_set: &mut WorkingSet<C>) -> SealedHeader {
        self.blocks
            .last(&mut working_set.accessory_state())
            .unwrap()
            .header
    }
}
