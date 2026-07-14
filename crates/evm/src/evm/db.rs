use core::error::Error;
#[cfg(not(feature = "native"))]
use std::cell::RefCell;
#[cfg(feature = "native")]
use std::collections::HashMap;

use alloy_primitives::{keccak256, Address, B256, U256};
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
            Self::UnknownCodeHash => {
                write!(f, "Code hash is unknown")
            }
        }
    }
}

// Session-lifetime cache of decoded bytecode, keyed by code hash.
//
// Bytecode is immutable per hash and every entry was keccak-verified on its
// first non-cached state read, so reusing the decoded Bytecode (refcounted
// bytes + shared jump table) only skips repeated decode work. Guest-only: a
// long-running native node must not grow an unbounded map.
//
// Every entry mirrors an entry of the cumulative offchain cache log, which is
// what decides whether a read consumes an offchain witness hint. The two must
// be dropped together, so [`clear_bytecode_cache`] is called whenever that log
// is pruned; otherwise a cached hit would skip a hint the prover did emit and
// the next offchain read would consume a value meant for someone else.
#[cfg(not(feature = "native"))]
std::thread_local! {
    static BYTECODE_CACHE: RefCell<std::collections::HashMap<B256, Bytecode>> =
        RefCell::default();
}

/// Drops every cached bytecode, so no entry outlives the cache-log entry it
/// mirrors. Called whenever the cumulative offchain cache log is pruned.
#[cfg(not(feature = "native"))]
pub(crate) fn clear_bytecode_cache() {
    BYTECODE_CACHE.with_borrow_mut(|cache| cache.clear());
}

/// Native execution never populates the bytecode cache, so there is nothing to
/// clear.
#[cfg(feature = "native")]
pub(crate) fn clear_bytecode_cache() {}

/// Whether the decoded bytecode of `code_hash` is already cached, which implies
/// the offchain cache log holds the same code.
#[cfg(not(feature = "native"))]
pub(crate) fn is_bytecode_cached(code_hash: &B256) -> bool {
    BYTECODE_CACHE.with_borrow(|cache| cache.contains_key(code_hash))
}

/// Native execution never populates the bytecode cache, so nothing is cached.
#[cfg(feature = "native")]
pub(crate) fn is_bytecode_cached(_code_hash: &B256) -> bool {
    false
}

/// Checks that `code` really is the preimage of `code_hash`.
///
/// Reading no code is not a mismatch: it means the offchain state holds no code
/// for `code_hash`, which callers report as [`DBError::UnknownCodeHash`] or as
/// "not stored yet".
fn verify_code_hash(code_hash: &B256, code: &Option<Bytecode>) -> Result<(), DBError> {
    code.as_ref().map_or(Ok(()), |code| {
        if *code_hash == keccak256(code.original_byte_slice()) {
            Ok(())
        } else {
            Err(DBError::CodeHashMismatch)
        }
    })
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

    /// Whether the offchain state already holds the code of `code_hash` — what
    /// decides if [`DatabaseCommit::commit`] still has to store it.
    ///
    /// The commit path only asks about code hashes missing from the bytecode
    /// cache, so this reaches the witness exactly when the code was never read
    /// this session either: `None` for a genuinely new contract, and its stored
    /// code for bytecode redeployed at a new address.
    ///
    /// The circuit verifies that value rather than trust it. An unverified read
    /// would plant prover-supplied bytecode in the offchain cache log, which a
    /// later [`Database::code_by_hash`] would hand to the EVM unchecked — its
    /// keccak check only runs on reads that miss the log. Natively the value
    /// comes from the node's own database, on the same read path `code_by_hash`
    /// already verifies.
    ///
    /// [`DatabaseCommit::commit`]: revm::DatabaseCommit::commit
    pub(crate) fn is_code_stored(&mut self, code_hash: &B256) -> bool {
        #[cfg(not(feature = "native"))]
        let code = self
            .evm
            .offchain_code
            .get_with_verification_on_no_cache(
                code_hash,
                |code| verify_code_hash(code_hash, code),
                &mut self.working_set.offchain_state(),
            )
            // `commit` cannot fail, and a mismatch means the witness lied about
            // code the circuit is about to trust: abort instead of proving it.
            .expect("Offchain code must be the preimage of its code hash");

        #[cfg(feature = "native")]
        let code = self
            .evm
            .offchain_code
            .get(code_hash, &mut self.working_set.offchain_state());

        code.is_some()
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
        // TODO move to new_raw_with_hash for better performance

        #[cfg(not(feature = "native"))]
        if let Some(code) = BYTECODE_CACHE.with_borrow(|cache| cache.get(&code_hash).cloned()) {
            return Ok(code);
        }

        if let Some(code) = self.evm.offchain_code.get_with_verification_on_no_cache(
            &code_hash,
            |code| verify_code_hash(&code_hash, code),
            &mut self.working_set.offchain_state(),
        )? {
            #[cfg(not(feature = "native"))]
            BYTECODE_CACHE.with_borrow_mut(|cache| {
                cache.insert(code_hash, code.clone());
            });

            Ok(code)
        } else {
            Err(DBError::UnknownCodeHash)
        }
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
