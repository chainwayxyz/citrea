use core::error::Error;
#[cfg(feature = "native")]
use std::collections::BTreeMap;

#[cfg(feature = "native")]
use alloy_eips::BlockNumHash;
#[cfg(feature = "native")]
use alloy_primitives::map::{AddressMap, B256HashMap};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
#[cfg(feature = "native")]
use reth_rpc_eth_types::revm_utils::OverrideBlockHashes;
use revm::context::DBErrorMarker;
#[cfg(feature = "native")]
use revm::primitives::BLOCK_HASH_HISTORY;
use revm::state::{AccountInfo as ReVmAccountInfo, Bytecode};
use revm::Database;
#[cfg(feature = "native")]
use sov_modules_api::StateVecAccessor;
use sov_modules_api::{SpecId, StateMapAccessor, WorkingSet};

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

#[cfg(feature = "native")]
pub(crate) struct RpcAccountOverride {
    pub(crate) info: ReVmAccountInfo,
    pub(crate) storage: B256HashMap<B256>,
    /// When set, slots missing from `storage` read as zero.
    pub(crate) replace_storage: bool,
}

pub(crate) struct EvmDb<'a, C: sov_modules_api::Context> {
    pub(crate) evm: &'a Evm<C>,
    pub(crate) working_set: &'a mut WorkingSet<C::Storage>,
    pub(crate) citrea_spec: SpecId,
    #[cfg(feature = "native")]
    account_overrides: AddressMap<RpcAccountOverride>,
    #[cfg(feature = "native")]
    code_overrides: B256HashMap<Bytecode>,
    /// Block hashes supplied by a block override.
    #[cfg(feature = "native")]
    block_hash_overrides: BTreeMap<u64, B256>,
    #[cfg(feature = "native")]
    pending_parent: Option<BlockNumHash>,
    /// Latest sealed height in the selected state when the simulated block number is overridden.
    #[cfg(feature = "native")]
    block_hash_base: Option<u64>,
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
            #[cfg(feature = "native")]
            account_overrides: AddressMap::default(),
            #[cfg(feature = "native")]
            code_overrides: B256HashMap::default(),
            #[cfg(feature = "native")]
            block_hash_overrides: BTreeMap::new(),
            #[cfg(feature = "native")]
            pending_parent: None,
            #[cfg(feature = "native")]
            block_hash_base: None,
        }
    }

    #[cfg(feature = "native")]
    pub(crate) fn with_pending_parent(mut self, parent: Option<BlockNumHash>) -> Self {
        self.pending_parent = parent;
        self
    }

    #[cfg(feature = "native")]
    pub(crate) fn set_block_hash_base(&mut self, number: u64) {
        self.block_hash_base = Some(number);
    }

    #[cfg(feature = "native")]
    pub(crate) fn override_account(&mut self, address: Address, account: RpcAccountOverride) {
        self.account_overrides.insert(address, account);
    }

    #[cfg(feature = "native")]
    pub(crate) fn override_code(&mut self, hash: B256, code: Bytecode) {
        self.code_overrides.insert(hash, code);
    }
}

#[cfg(feature = "native")]
impl<C: sov_modules_api::Context> OverrideBlockHashes for EvmDb<'_, C> {
    fn override_block_hashes(&mut self, hashes: BTreeMap<u64, B256>) {
        self.block_hash_overrides.extend(hashes);
    }
}

impl<C: sov_modules_api::Context> Database for EvmDb<'_, C> {
    type Error = DBError;

    fn basic(&mut self, address: Address) -> Result<Option<ReVmAccountInfo>, Self::Error> {
        #[cfg(feature = "native")]
        if let Some(account) = self.account_overrides.get(&address) {
            return Ok(Some(account.info.clone()));
        }

        let db_account = self.evm.account_info(&address, self.working_set);
        Ok(db_account.map(Into::into))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        #[cfg(feature = "native")]
        if let Some(code) = self.code_overrides.get(&code_hash) {
            return Ok(code.clone());
        }

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
        #[cfg(feature = "native")]
        if let Some(account) = self.account_overrides.get(&address) {
            if let Some(value) = account.storage.get(&B256::from(index)) {
                return Ok(U256::from_be_bytes(value.0));
            }
            if account.replace_storage {
                return Ok(U256::ZERO);
            }
        }

        let storage_value = self
            .evm
            .storage_get(&address, &index, self.working_set)
            .unwrap_or_default();

        Ok(storage_value)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        #[cfg(feature = "native")]
        {
            if let Some(hash) = self.block_hash_overrides.get(&number) {
                return Ok(*hash);
            }
            if let Some(parent) = self.pending_parent.filter(|parent| parent.number == number) {
                return Ok(parent.hash);
            }
            if let Some(base) = self.block_hash_base {
                // Retained state can still contain a hash after its native header is pruned.
                // The modulo-indexed buffer ends at the sealed block's parent.
                let distance = base.saturating_sub(number);
                if (1..=BLOCK_HASH_HISTORY).contains(&distance) {
                    if let Some(hash) = self.evm.blockhash_get(number, self.working_set) {
                        return Ok(hash);
                    }
                }
                // Reth looks up canonical headers independently of historical account state.
                // <https://github.com/paradigmxyz/reth/blob/ed7da87da4de340a437bf46f39a7e1397ac82065/crates/storage/provider/src/providers/state/historical.rs#L271-L277>
                let hash = usize::try_from(number).ok().and_then(|index| {
                    self.evm
                        .blocks
                        .get(index, &mut self.working_set.base_accessory_state())
                        .map(|block| block.header.hash())
                });
                return Ok(hash.unwrap_or_default());
            }
        }

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
        #[cfg(feature = "native")]
        if self.account_overrides.contains_key(address) {
            return false;
        }

        // As the diff size is calculated in `Handler::output` before `DataBase::commit`,
        // We wouldn't have them in the account indices map
        // So this can tell us if the account is newly created
        !self.evm.account_exists(address, self.working_set)
    }
}

impl<C: sov_modules_api::Context> AccountExistsProvider for &mut EvmDb<'_, C> {
    fn is_first_time_committing_address(&mut self, address: &Address) -> bool {
        (**self).is_first_time_committing_address(address)
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
