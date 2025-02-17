#[cfg(feature = "native")]
use std::collections::HashMap;

use alloy_primitives::{keccak256, Address, B256};
use revm::primitives::{AccountInfo as ReVmAccountInfo, Bytecode, SpecId as EvmSpecId, U256};
use revm::Database;
use sov_modules_api::{SpecId as CitreaSpecId, StateMapAccessor, WorkingSet};

#[cfg(feature = "native")]
use super::AccountInfo;
use crate::{citrea_spec_id_to_evm_spec_id, Evm};

// infallible
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DBError {
    CodeHashMismatch,
}

impl std::fmt::Display for DBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodeHashMismatch => {
                write!(f, "Code does not match provided hash")
            }
        }
    }
}

pub(crate) struct EvmDb<'a, C: sov_modules_api::Context> {
    pub(crate) evm: &'a Evm<C>,
    pub(crate) working_set: &'a mut WorkingSet<C::Storage>,
    pub(crate) citrea_spec: CitreaSpecId,
    pub(crate) evm_spec: EvmSpecId,
}

impl<'a, C: sov_modules_api::Context> EvmDb<'a, C> {
    pub(crate) fn new(
        evm: &'a Evm<C>,
        working_set: &'a mut WorkingSet<C::Storage>,
        citrea_spec: CitreaSpecId,
    ) -> Self {
        Self {
            evm,
            working_set,
            citrea_spec,
            evm_spec: citrea_spec_id_to_evm_spec_id(citrea_spec),
        }
    }

    #[cfg(feature = "native")]
    pub(crate) fn override_block_hash(&mut self, number: u64, hash: B256) {
        self.evm
            .latest_block_hashes
            .set(&U256::from(number), &hash, self.working_set);
    }

    #[cfg(feature = "native")]
    pub(crate) fn override_account(&mut self, account: &Address, info: AccountInfo) {
        self.evm
            .account_set(account, &info, self.citrea_spec, self.working_set);
    }

    #[cfg(feature = "native")]
    pub(crate) fn override_set_account_storage(
        &mut self,
        account: &Address,
        state_diff: HashMap<B256, B256, alloy_primitives::map::FbBuildHasher<32>>,
    ) {
        for (slot, value) in state_diff {
            self.evm.storage_set(
                account,
                &slot.into(),
                &U256::from_be_bytes(value.0),
                self.citrea_spec,
                self.working_set,
            );
        }
    }
}

impl<'a, C: sov_modules_api::Context> Database for EvmDb<'a, C> {
    type Error = DBError;

    fn basic(&mut self, address: Address) -> Result<Option<ReVmAccountInfo>, Self::Error> {
        let db_account = self
            .evm
            .account_info(&address, self.citrea_spec, self.working_set);
        Ok(db_account.map(Into::into))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // TODO move to new_raw_with_hash for better performance

        // If CANCUN or later forks are activated, try to fetch code from offchain storage
        // first. This is to prevent slower lookups in `code`.
        if self.evm_spec.is_enabled_in(EvmSpecId::CANCUN) {
            if let Some(code) = self.evm.offchain_code.get_with_verification_on_no_cache(
                &code_hash,
                |val| {
                    // if code is read as None,
                    // we don't have code for the given code_hash
                    // return true in that case so we return None from get_with_verification_on_no_cache
                    val.as_ref().map_or(Ok(()), |code| {
                        if *code_hash == keccak256(code.original_byte_slice()) {
                            Ok(())
                        } else {
                            Err(DBError::CodeHashMismatch)
                        }
                    })
                },
                &mut self.working_set.offchain_state(),
            )? {
                return Ok(code);
            }
        }
        let code = self.evm.code.get(&code_hash, self.working_set);
        if let Some(code) = code {
            // Gradually migrate contract codes into the offchain code state map.
            if self.evm_spec.is_enabled_in(EvmSpecId::CANCUN) {
                self.evm.offchain_code.set(
                    &code_hash,
                    &code,
                    &mut self.working_set.offchain_state(),
                );
            }
            Ok(code)
        } else {
            Ok(Default::default())
        }
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let storage_value = self
            .evm
            .storage_get(&address, &index, self.citrea_spec, self.working_set)
            .unwrap_or_default();

        Ok(storage_value)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        let block_hash = self
            .evm
            .latest_block_hashes
            .get(&U256::from(number), self.working_set)
            .unwrap_or(B256::ZERO);

        Ok(block_hash)
    }
}

#[cfg(feature = "native")]
impl From<DBError> for reth_rpc_eth_types::error::EthApiError {
    fn from(_value: DBError) -> Self {
        reth_rpc_eth_types::error::EthApiError::InternalEthError
    }
}
