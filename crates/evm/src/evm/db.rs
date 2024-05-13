use reth_primitives::{Address, B256};
use revm::primitives::{AccountInfo as ReVmAccountInfo, Bytecode, U256};
use revm::Database;
use sov_modules_api::{StateMapAccessor, WorkingSet};
use sov_state::codec::BcsCodec;

use super::DbAccount;

pub(crate) struct EvmDb<'a, C: sov_modules_api::Context> {
    pub(crate) accounts: sov_modules_api::StateMap<Address, DbAccount, BcsCodec>,
    pub(crate) code: sov_modules_api::StateMap<B256, Bytecode, BcsCodec>,
    pub(crate) last_block_hashes: sov_modules_api::StateMap<U256, B256, BcsCodec>,
    pub(crate) working_set: &'a mut WorkingSet<C>,
}

impl<'a, C: sov_modules_api::Context> EvmDb<'a, C> {
    pub(crate) fn new(
        accounts: sov_modules_api::StateMap<Address, DbAccount, BcsCodec>,
        code: sov_modules_api::StateMap<B256, Bytecode, BcsCodec>,
        last_block_hashes: sov_modules_api::StateMap<U256, B256, BcsCodec>,
        working_set: &'a mut WorkingSet<C>,
    ) -> Self {
        Self {
            accounts,
            code,
            last_block_hashes,
            working_set,
        }
    }
}

// infallible
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DBError {}

impl std::fmt::Display for DBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EVM Infallible DBError")
    }
}

// impl stdError for dberror
impl std::error::Error for DBError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl<'a, C: sov_modules_api::Context> Database for EvmDb<'a, C> {
    type Error = DBError;

    fn basic(&mut self, address: Address) -> Result<Option<ReVmAccountInfo>, Self::Error> {
        let db_account = self.accounts.get(&address, self.working_set);
        Ok(db_account.map(|acc| acc.info.into()))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // TODO move to new_raw_with_hash for better performance
        Ok(self
            .code
            .get(&code_hash, self.working_set)
            .unwrap_or_default())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let storage_value: U256 = if let Some(acc) = self.accounts.get(&address, self.working_set) {
            acc.storage
                .get(&index, self.working_set)
                .unwrap_or_default()
        } else {
            U256::default()
        };

        Ok(storage_value)
    }

    fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
        let block_hash = self
            .last_block_hashes
            .get(&number, self.working_set)
            .unwrap_or(B256::ZERO);

        Ok(block_hash)
    }
}

#[cfg(feature = "native")]
impl From<DBError> for reth_rpc::eth::error::EthApiError {
    fn from(_value: DBError) -> Self {
        reth_rpc::eth::error::EthApiError::InternalEthError
    }
}
