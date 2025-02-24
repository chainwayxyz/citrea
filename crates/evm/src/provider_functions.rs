use alloy_primitives::{Address, U256};
#[cfg(feature = "native")]
use reth_primitives::SealedHeader;
use sha2::Digest;
#[cfg(feature = "native")]
use sov_modules_api::StateVecAccessor;
use sov_modules_api::{SpecId as CitreaSpecId, StateMapAccessor, StateValueAccessor, WorkingSet};
use sov_state::codec::BcsCodec;
use sov_state::storage::StorageKey;

use crate::{AccountInfo, DbAccount, Evm};

impl<C: sov_modules_api::Context> Evm<C> {
    /// Returns the account info at the given address.
    pub fn account_exists(
        &self,
        address: &Address,
        citrea_spec: CitreaSpecId,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> bool {
        if citrea_spec >= CitreaSpecId::Fork2 {
            if self.account_idxs.get(address, working_set).is_some() {
                true
            } else {
                // here goes migration from prefork2 to postfork2
                if let Some(info) = self.account_info_prefork2(address, working_set) {
                    self.account_set_postfork2(address, &info, working_set);
                    true
                } else {
                    false
                }
            }
        } else {
            self.account_info_prefork2(address, working_set).is_some()
        }
    }

    /// Get account info < Fork2
    pub fn account_info_prefork2(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Option<AccountInfo> {
        self.accounts_prefork2.get(address, working_set)
    }

    /// Get account info >= Fork2
    pub fn account_info_postfork2(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Option<AccountInfo> {
        let idx = self.account_idxs.get(address, working_set)?;
        self.accounts_postfork2.get(&idx, working_set)
    }

    /// Returns the account info at the given address.
    pub fn account_info(
        &self,
        address: &Address,
        citrea_spec: CitreaSpecId,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Option<AccountInfo> {
        if citrea_spec >= CitreaSpecId::Fork2 {
            let res = self.account_info_postfork2(address, working_set);
            match res {
                Some(info) => Some(info),
                None => {
                    // here goes migration from prefork2 to postfork2
                    let info = self.account_info_prefork2(address, working_set)?;
                    self.account_set_postfork2(address, &info, working_set);
                    Some(info)
                }
            }
        } else {
            self.account_info_prefork2(address, working_set)
        }
    }

    fn account_set_prefork2(
        &self,
        address: &Address,
        info: &AccountInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        self.accounts_prefork2.set(address, info, working_set)
    }

    fn account_set_postfork2(
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
        self.accounts_postfork2.set(&idx, info, working_set)
    }

    /// Set the account (probably allocate an index for it) at the given address.
    pub fn account_set(
        &self,
        address: &Address,
        info: &AccountInfo,
        citrea_spec: CitreaSpecId,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        if citrea_spec >= CitreaSpecId::Fork2 {
            self.account_set_postfork2(address, info, working_set)
        } else {
            self.account_set_prefork2(address, info, working_set)
        }
    }

    /// Delete the account at the given address.
    pub(crate) fn account_delete(
        &self,
        address: &Address,
        citrea_spec: CitreaSpecId,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        if citrea_spec >= CitreaSpecId::Fork2 {
            if let Some(idx) = self.account_idxs.get(address, working_set) {
                self.accounts_postfork2.delete(&idx, working_set)
            }
        } else {
            self.accounts_prefork2.delete(address, working_set)
        }
    }

    /// Get the address of a storage key for the given account
    pub fn get_storage_address(account: &Address, key: &U256) -> U256 {
        let mut hasher: sha2::Sha256 = sha2::Digest::new_with_prefix(account.as_slice());
        hasher.update(key.as_le_slice());
        let arr = hasher.finalize();
        U256::from_le_slice(&arr)
    }

    /// Get the storage key for the given account and key for pre fork2
    pub fn get_storage_key_pre_fork2(account: &Address, key: &U256) -> StorageKey {
        let prefix = DbAccount::create_storage_prefix(account);

        StorageKey::new(&prefix, key, &BcsCodec {})
    }

    /// Get storage value < Fork2
    pub fn storage_get_prefork2(
        &self,
        account: &Address,
        key: &U256,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Option<U256> {
        let db_account = DbAccount::new(account);
        db_account.storage.get(key, working_set)
    }

    /// Get storage value >= Fork2
    pub fn storage_get_postfork2(
        &self,
        account: &Address,
        key: &U256,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Option<U256> {
        let kaddr = Self::get_storage_address(account, key);
        self.storage.get(&kaddr, working_set)
    }

    /// Get the storage value for the given (account, key)
    pub fn storage_get(
        &self,
        account: &Address,
        key: &U256,
        citrea_spec: CitreaSpecId,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Option<U256> {
        if citrea_spec >= CitreaSpecId::Fork2 {
            let value = self.storage_get_postfork2(account, key, working_set);
            match value {
                Some(value) => Some(value),
                None => {
                    // here goes migration from prefork2 to postfork2
                    let value = self.storage_get_prefork2(account, key, working_set)?;
                    self.storage_set_postfork2(account, key, &value, working_set);
                    Some(value)
                }
            }
        } else {
            self.storage_get_prefork2(account, key, working_set)
        }
    }

    fn storage_set_postfork2(
        &self,
        account: &Address,
        key: &U256,
        value: &U256,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        let kaddr = Self::get_storage_address(account, key);
        self.storage.set(&kaddr, value, working_set)
    }

    fn storage_set_prefork2(
        &self,
        account: &Address,
        key: &U256,
        value: &U256,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        let db_account = DbAccount::new(account);
        db_account.storage.set(key, value, working_set)
    }

    /// Set the storage value for the given (account, key)
    pub(crate) fn storage_set(
        &self,
        account: &Address,
        key: &U256,
        value: &U256,
        citrea_spec: CitreaSpecId,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        if citrea_spec >= CitreaSpecId::Fork2 {
            self.storage_set_postfork2(account, key, value, working_set)
        } else {
            self.storage_set_prefork2(account, key, value, working_set)
        }
    }

    /// Remove all storage values for given [(account, k) for k in keys]
    pub(crate) fn storage_delete(
        &self,
        account: &Address,
        keys: &[U256],
        citrea_spec: CitreaSpecId,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        if citrea_spec >= CitreaSpecId::Fork2 {
            for key in keys {
                let kaddr = Self::get_storage_address(account, key);
                self.storage.delete(&kaddr, working_set)
            }
        } else {
            let db_account = DbAccount::new(account);
            for key in keys {
                db_account.storage.delete(key, working_set)
            }
        }
    }

    #[cfg(feature = "native")]
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
            .expect("Head block must be set")
            .header
    }
}
