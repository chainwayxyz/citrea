use core::error::Error;
#[cfg(feature = "native")]
use std::collections::HashMap;

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use revm::context::DBErrorMarker;
use revm::state::{AccountInfo as ReVmAccountInfo, Bytecode};
use revm::Database;
use sov_modules_api::{SpecId, StateMapAccessor, WorkingSet};

#[cfg(feature = "native")]
use super::AccountInfo;
use crate::Evm;

// infallible
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DBError {
    CodeHashMismatch,
    MalformedCode,
    UnknownCodeHash,
}

impl DBErrorMarker for DBError {}
impl Error for DBError {}

impl std::fmt::Display for DBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodeHashMismatch => {
                write!(f, "Code does not match provided hash")
            }
            Self::MalformedCode => {
                write!(f, "Stored code is malformed")
            }
            Self::UnknownCodeHash => {
                write!(f, "Code hash is unknown")
            }
        }
    }
}

/// Extracts the bytes that `code_hash` is supposed to commit to, without trusting
/// any of the value's derived fields.
///
/// Returns `None` when the value is structurally malformed
fn committed_bytes(code: &Bytecode) -> Option<Bytes> {
    match code {
        Bytecode::LegacyAnalyzed(analyzed) => {
            let padded = analyzed.bytecode();
            let original_len = analyzed.original_len();
            (original_len <= padded.len()).then(|| padded.slice(..original_len))
        }
        Bytecode::Eof(eof) => Some(eof.raw().clone()),
        Bytecode::Eip7702(eip7702) => Some(eip7702.raw().clone()),
    }
}

/// Checks that `code` is exactly what `code_hash` commits to, including every field revm
/// derives from the code bytes.
fn verify_code(code_hash: B256, code: &Bytecode) -> Result<(), DBError> {
    let committed = committed_bytes(code).ok_or(DBError::MalformedCode)?;
    if keccak256(&committed) != code_hash {
        return Err(DBError::CodeHashMismatch);
    }

    let canonical = Bytecode::new_raw_checked(committed).map_err(|_| DBError::MalformedCode)?;
    if canonical != *code {
        return Err(DBError::MalformedCode);
    }

    Ok(())
}

pub(crate) struct EvmDb<'a, C: sov_modules_api::Context> {
    pub(crate) evm: &'a Evm<C>,
    pub(crate) working_set: &'a mut WorkingSet<C::Storage>,
    pub(crate) citrea_spec: SpecId,
}

impl<'a, C: sov_modules_api::Context> EvmDb<'a, C> {
    pub(crate) fn new(
        evm: &'a Evm<C>,
        working_set: &'a mut WorkingSet<C::Storage>,
        citrea_spec: SpecId,
    ) -> Self {
        Self {
            evm,
            working_set,
            citrea_spec,
        }
    }

    #[cfg(feature = "native")]
    pub(crate) fn override_block_hash(&mut self, number: u64, hash: B256) {
        self.evm.blockhash_set(number, &hash, self.working_set);
    }

    #[cfg(feature = "native")]
    pub(crate) fn override_account(&mut self, account: &Address, info: AccountInfo) {
        self.evm.account_set(account, &info, self.working_set);
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
                self.working_set,
            );
        }
    }
}

impl<C: sov_modules_api::Context> Database for EvmDb<'_, C> {
    type Error = DBError;

    fn basic(&mut self, address: Address) -> Result<Option<ReVmAccountInfo>, Self::Error> {
        let db_account = self.evm.account_info(&address, self.working_set);
        Ok(db_account.map(Into::into))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.evm
            .offchain_code
            .get_with_verification_on_no_cache(
                &code_hash,
                |val| {
                    val.as_ref()
                        .map_or(Ok(()), |code| verify_code(code_hash, code))
                },
                &mut self.working_set.offchain_state(),
            )?
            .ok_or(DBError::UnknownCodeHash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let storage_value = self
            .evm
            .storage_get(&address, &index, self.working_set)
            .unwrap_or_default();

        Ok(storage_value)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        // no need to check block number ranges
        // revm already checks it

        Ok(self
            .evm
            .blockhash_get(number, self.working_set)
            .expect("Block hash does not exist for range checked by revm"))
    }
}

/// A trait to check if an account is newly created.
/// This is useful when calculating diff size for a transactions
pub trait AccountExistsProvider {
    /// Check if an account is newly created
    /// By querying `Evm::account_exists`
    fn is_first_time_committing_address(&mut self, address: &Address) -> bool;
}

impl<C: sov_modules_api::Context> AccountExistsProvider for EvmDb<'_, C> {
    fn is_first_time_committing_address(&mut self, address: &Address) -> bool {
        // As the diff size is calculated in `Handler::output` before `DataBase::commit`,
        // We wouldn't have them in the account indices map
        // So this can tell us if the account is newly created
        !self.evm.account_exists(address, self.working_set)
    }
}

impl<C: sov_modules_api::Context> AccountExistsProvider for &mut EvmDb<'_, C> {
    fn is_first_time_committing_address(&mut self, address: &Address) -> bool {
        // As the diff size is calculated in `Handler::output` before `DataBase::commit`,
        // We wouldn't have them in the account indices map
        // So this can tell us if the account is newly created
        !self.evm.account_exists(address, self.working_set)
    }
}

#[cfg(feature = "native")]
pub mod immutable {
    use std::cell::RefCell;

    use alloy_primitives::{Address, B256, U256};
    use revm::state::{AccountInfo as ReVmAccountInfo, Bytecode};
    use revm::{Database, DatabaseRef};

    use super::{AccountExistsProvider, DBError, EvmDb};

    pub(crate) struct EvmDbRef<'a, 'b, C: sov_modules_api::Context> {
        pub(crate) evm_db: RefCell<&'b mut EvmDb<'a, C>>,
    }

    impl<'a, 'b, C: sov_modules_api::Context> EvmDbRef<'a, 'b, C> {
        pub(crate) fn new(evm_db: &'b mut EvmDb<'a, C>) -> Self {
            Self {
                evm_db: std::cell::RefCell::new(evm_db),
            }
        }
    }

    impl<C: sov_modules_api::Context> Database for EvmDbRef<'_, '_, C> {
        type Error = DBError;

        fn basic(&mut self, address: Address) -> Result<Option<ReVmAccountInfo>, Self::Error> {
            self.basic_ref(address)
        }

        fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
            self.code_by_hash_ref(code_hash)
        }

        fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
            self.storage_ref(address, index)
        }

        fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
            self.block_hash_ref(number)
        }
    }

    impl<C: sov_modules_api::Context> revm::DatabaseRef for EvmDbRef<'_, '_, C> {
        type Error = DBError;

        fn basic_ref(&self, address: Address) -> Result<Option<ReVmAccountInfo>, Self::Error> {
            self.evm_db.borrow_mut().basic(address)
        }

        fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
            self.evm_db.borrow_mut().code_by_hash(code_hash)
        }

        fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
            self.evm_db.borrow_mut().storage(address, index)
        }

        fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
            self.evm_db.borrow_mut().block_hash(number)
        }
    }

    // FIXME: https://github.com/paradigmxyz/revm-inspectors/pull/278
    impl<C: sov_modules_api::Context> revm::DatabaseCommit for EvmDbRef<'_, '_, C> {
        fn commit(&mut self, _changes: revm::primitives::HashMap<Address, revm::state::Account>) {
            // do nothing
        }
    }

    impl<C: sov_modules_api::Context> AccountExistsProvider for &mut EvmDbRef<'_, '_, C> {
        fn is_first_time_committing_address(&mut self, address: &Address) -> bool {
            self.evm_db
                .borrow_mut()
                .is_first_time_committing_address(address)
        }
    }
}

#[cfg(feature = "native")]
impl From<DBError> for reth_rpc_eth_types::error::EthApiError {
    fn from(_value: DBError) -> Self {
        reth_rpc_eth_types::error::EthApiError::InternalEthError
    }
}
