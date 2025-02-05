use alloy_primitives::{Address, U256};
use reth_primitives::SealedHeader;
use sov_modules_api::{StateMapAccessor, StateValueAccessor, StateVecAccessor, WorkingSet};

use crate::{AccountInfo, Evm};

impl<C: sov_modules_api::Context> Evm<C> {
    /// Returns the account info at the given address.
    pub fn account_exists(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> bool {
        self.account_idxs.get(address, working_set).is_some()
    }

    /// Returns the account info at the given address.
    pub fn account_info(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Option<AccountInfo> {
        let idx = self.account_idxs.get(address, working_set)?;
        self.accounts.get(&idx, working_set)
    }

    /// Set the account (probably allocate an index for it) at the given address.
    pub fn account_set(
        &self,
        address: &Address,
        info: &AccountInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        let idx = if let Some(idx) = self.account_idxs.get(address, working_set) {
            idx
        } else {
            let curr_idx = self.account_amount.get(working_set).unwrap_or_default();
            self.account_idxs.set(address, &curr_idx, working_set);
            self.account_amount.set(&(curr_idx + 1), working_set);
            curr_idx
        };
        self.accounts.set(&idx, info, working_set)
    }

    /// Delete the account (not its index) at the given address.
    pub fn account_delete(&self, address: &Address, working_set: &mut WorkingSet<C::Storage>) {
        if let Some(idx) = self.account_idxs.get(address, working_set) {
            self.accounts.delete(&idx, working_set)
        }
    }

    /// Get the address of a storage key for the given account
    fn get_storage_address(account: &Address, key: &U256) -> U256 {
        let mut hasher: sha2::Sha256 = sha2::Digest::new_with_prefix(account.as_slice());
        sha2::digest::Update::update(&mut hasher, key.as_le_slice());
        let arr = sha2::Digest::finalize(hasher);
        U256::from_le_slice(&arr)
    }

    /// Get the storage value for the given (account, key)
    pub fn storage_get(
        &self,
        account: &Address,
        key: &U256,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Option<U256> {
        let kaddr = Self::get_storage_address(account, key);
        self.storage.get(&kaddr, working_set)
    }

    /// Set the storage value for the given (account, key)
    pub(crate) fn storage_set(
        &self,
        account: &Address,
        key: &U256,
        value: &U256,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        let kaddr = Self::get_storage_address(account, key);
        self.storage.set(&kaddr, value, working_set)
    }

    /// Remove all storage values for given [(account, k) for k in keys]
    pub(crate) fn storage_delete(
        &self,
        account: &Address,
        keys: &[U256],
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        for key in keys {
            let kaddr = Self::get_storage_address(account, key);
            self.storage.delete(&kaddr, working_set);
        }
    }

    /// Returns the sealed head block.
    pub fn last_sealed_header(&self, working_set: &mut WorkingSet<C::Storage>) -> SealedHeader {
        self.blocks_rlp
            .last(&mut working_set.accessory_state())
            .or_else(|| {
                //  upgrading from v0.5.7 to v0.6+ requires a codec change
                // this only applies to the sequencer
                // which will only query the genesis block and the head block
                // right after the upgrade
                self.blocks
                    .last(&mut working_set.accessory_state())
                    .map(Into::into)
            })
            .unwrap()
            .header
    }
}
