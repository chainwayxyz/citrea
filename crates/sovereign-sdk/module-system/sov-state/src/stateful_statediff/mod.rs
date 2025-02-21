/// Compression primitives
pub mod compression;

use std::collections::BTreeMap;
use std::io::{Error, ErrorKind, Read, Write};

use alloy_primitives::{Address, B256, U256};
use borsh::{BorshDeserialize, BorshSerialize};
use compression::{CodeHashChange, SlotChange};
use serde::{Deserialize, Serialize};
use sov_modules_core::{CacheKey, CacheValue};
use sov_rollup_interface::RefCount;

pub(crate) struct PreState {
    evm_accounts_prefork2: BTreeMap<Address, Option<DbAccountInfo>>,
    evm_storage_prefork2: BTreeMap<Address, BTreeMap<U256, Option<U256>>>,
    evm_accounts: BTreeMap<u64, Option<DbAccountInfo>>,
    evm_storage: BTreeMap<U256, Option<U256>>,
}

fn borsh_u256_from_slice(v: impl AsRef<[u8]>) -> U256 {
    let s: [u64; 4] = borsh::from_slice(v.as_ref()).unwrap();
    U256::from_limbs(s)
}

pub(crate) fn build_pre_state(ordered_reads: &[(CacheKey, Option<CacheValue>)]) -> PreState {
    // We need the first values we read. So we traverse from the beginning.
    // We are only interested in keys -> values only when we see them the first time.
    // And we need only Evm accounts and storage, because that's the only
    // thing we need to compress with zksync algorithms.
    let mut evm_accounts_prefork2: BTreeMap<Address, Option<DbAccountInfo>> = BTreeMap::new();
    let mut evm_storage_prefork2: BTreeMap<Address, _> = BTreeMap::new();
    let mut evm_accounts = BTreeMap::new();
    let mut evm_storage = BTreeMap::new();

    for (k, v) in ordered_reads {
        let (key, value) = (k.key.as_ref(), v.as_ref().map(|v| v.value.as_ref()));
        match &key[..6] {
            _account_prefork2 @ b"Evm/a/" => {
                let address: Address = bcs::from_bytes(&key[6..]).unwrap();
                evm_accounts_prefork2.entry(address).or_insert_with(|| {
                    let info: Option<DbAccountInfo> =
                        value.as_ref().map(|v| bcs::from_bytes(v).unwrap());
                    info
                });
            }
            _storage_prefork2 @ b"Evm/s/" => {
                let address = Address::from_slice(&key[6..(6 + 20)]);
                let storage_key: U256 = bcs::from_bytes(&key[26..]).unwrap();

                let account_storage: &mut BTreeMap<U256, Option<U256>> =
                    evm_storage_prefork2.entry(address).or_default();

                account_storage.entry(storage_key).or_insert_with(|| {
                    let storage_value: Option<U256> = value.map(|v| bcs::from_bytes(v).unwrap());
                    storage_value
                });
            }
            _account @ b"Evm/t/" => {
                let index: u64 = borsh::from_slice(&key[6..]).unwrap();
                evm_accounts.entry(index).or_insert_with(|| {
                    let info: Option<DbAccountInfo> = value.map(|v| borsh::from_slice(v).unwrap());
                    info
                });
            }
            _storage @ b"Evm/S/" => {
                let storage_key: U256 = borsh_u256_from_slice(&key[6..]);

                evm_storage
                    .entry(storage_key)
                    .or_insert_with(|| value.map(borsh_u256_from_slice));
            }
            _ => {}
        }
    }
    PreState {
        evm_accounts_prefork2,
        evm_storage_prefork2,
        evm_accounts,
        evm_storage,
    }
}

/// A diff of the state, represented as a list of key-value pairs.
pub type UnparsedStateDiff = Vec<(RefCount<[u8]>, Option<RefCount<[u8]>>)>;

pub(crate) struct PostState {
    evm_accounts_prefork2: BTreeMap<Address, Option<DbAccountInfo>>,
    evm_storage_prefork2: BTreeMap<Address, BTreeMap<U256, Option<U256>>>,
    evm_accounts: BTreeMap<u64, Option<DbAccountInfo>>,
    evm_account_address: Vec<Address>,
    evm_account_count: Option<u64>,
    evm_storage: BTreeMap<U256, Option<U256>>,
    evm_latest_block_hashes: Vec<(u64, B256)>,
    unparsed: UnparsedStateDiff,
}

pub(crate) fn build_post_state<'a>(
    ordered_writes: impl Iterator<Item = (&'a CacheKey, &'a Option<CacheValue>)>,
) -> PostState {
    // We need the last values we write. So we traverse from the end.
    let mut evm_accounts_prefork2: BTreeMap<Address, Option<DbAccountInfo>> = BTreeMap::new();
    let mut evm_storage_prefork2: BTreeMap<Address, _> = BTreeMap::new();
    let mut evm_accounts = BTreeMap::new();
    let mut evm_account_address = Vec::new();
    let mut evm_account_count = None;
    let mut evm_storage = BTreeMap::new();
    let mut evm_latest_block_hashes = Vec::new();
    let mut unparsed = UnparsedStateDiff::new();

    for (cache_key, cache_value) in ordered_writes.into_iter() {
        let (key, value) = (
            cache_key.key.as_ref(),
            cache_value.as_ref().map(|v| v.value.as_ref()),
        );
        match &key[..6] {
            _account_prefork2 @ b"Evm/a/" => {
                // Only the first key -> value
                let address: Address = bcs::from_bytes(&key[6..]).unwrap();
                evm_accounts_prefork2.entry(address).or_insert_with(|| {
                    let info: Option<DbAccountInfo> =
                        value.as_ref().map(|v| bcs::from_bytes(v).unwrap());
                    info
                });
            }
            _storage_prefork2 @ b"Evm/s/" => {
                // Only the first key -> value
                let address = Address::from_slice(&key[6..(6 + 20)]);
                let storage_key: U256 = bcs::from_bytes(&key[26..]).unwrap();

                let account_storage: &mut BTreeMap<U256, Option<U256>> =
                    evm_storage_prefork2.entry(address).or_default();

                account_storage.entry(storage_key).or_insert_with(|| {
                    let storage_value: Option<U256> =
                        value.as_ref().map(|v| bcs::from_bytes(v).unwrap());
                    storage_value
                });
            }
            _account @ b"Evm/t/" => {
                let index: u64 = borsh::from_slice(&key[6..]).unwrap();
                evm_accounts.entry(index).or_insert_with(|| {
                    let info: Option<DbAccountInfo> = value.map(|v| borsh::from_slice(v).unwrap());
                    info
                });
            }
            _evm_account_address @ b"Evm/i/" => {
                // Ignore removals
                if value.is_some() {
                    let address = Address::from_slice(&key[6..(6 + 20)]);
                    // ignore indices because we can recover them from account count
                    evm_account_address.push(address);
                }
            }
            _account_count @ b"Evm/n/" => {
                if evm_account_count.is_none() {
                    // Ignore removals
                    if let Some(value) = value {
                        let count = borsh::from_slice(value).unwrap();
                        evm_account_count = Some(count);
                    }
                }
            }
            _storage @ b"Evm/S/" => {
                let storage_key: U256 = borsh_u256_from_slice(&key[6..]);

                evm_storage
                    .entry(storage_key)
                    .or_insert_with(|| value.map(borsh_u256_from_slice));
            }
            _latest_block_hashes @ b"Evm/h/" => {
                // Ignore removals
                if let Some(value) = value {
                    let block_number: U256 = bcs::from_bytes(&key[6..]).unwrap();
                    let block_number: u64 = block_number
                        .try_into()
                        .expect("Block number should fit into u64");
                    let block_hash: B256 = bcs::from_bytes(value).unwrap();

                    evm_latest_block_hashes.push((block_number, block_hash));
                }
            }
            _ => {
                // Here goes:
                // - SoftConfirmationRuleEnforcer/authority/
                // - SoftConfirmationRuleEnforcer/data/
                // - Accounts/public_keys_post_fork2/
                // - Accounts/accounts_post_fork2/
                // - Evm/cfg/
                // - Evm/head/
                // - Evm/head_rlp/
                // - Evm/c/ - old code, new is Evm/occ/ which is not stored on DA
                // - Evm/last_l1_hash/

                // let hx_key = alloy_primitives::hex::encode(key);
                // println!("unknown key: {}", hx_key);
                let key_bytes = cache_key.key.clone();
                let value_bytes = cache_value.as_ref().map(|v| v.value.clone());

                unparsed.push((key_bytes, value_bytes));
            }
        }
    }
    PostState {
        evm_accounts_prefork2,
        evm_storage_prefork2,
        evm_accounts,
        evm_account_count,
        evm_account_address,
        evm_storage,
        evm_latest_block_hashes,
        unparsed,
    }
}

/// Reflects account change
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct AccountChange {
    balance: SlotChange,
    nonce: SlotChange,
    code_hash: CodeHashChange,
}

/// Reflects storage change
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct StorageChange {
    #[borsh(serialize_with = "ser_btree_u256", deserialize_with = "der_btree_u256")]
    storage: BTreeMap<U256, Option<SlotChange>>,
}

/// Reflects new Evm.latest_block_hashes
// TODO maybe keep (u64, B256) in StatefulStateDiff but compress on borsh serde?
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct LatestBlockHashes {
    starting_block_number: u64,
    #[borsh(serialize_with = "ser_vec_b256", deserialize_with = "der_vec_b256")]
    block_hashes: Vec<B256>,
}

/// Reflects all state change
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct StatefulStateDiff {
    // TODO: Remove before mainnet
    #[borsh(
        serialize_with = "ser_btree_address",
        deserialize_with = "der_btree_address"
    )]
    evm_accounts_prefork2: BTreeMap<Address, AccountChange>,

    // TODO: Remove before mainnet
    #[borsh(
        serialize_with = "ser_btree_address",
        deserialize_with = "der_btree_address"
    )]
    evm_storage_prefork2: BTreeMap<Address, StorageChange>,

    evm_accounts: Vec<(u64, Option<AccountChange>)>,
    #[borsh(
        serialize_with = "ser_vec_address",
        deserialize_with = "der_vec_address"
    )]
    evm_account_address: Vec<Address>,

    evm_account_count: Option<u64>,
    #[borsh(
        serialize_with = "ser_evm_storage",
        deserialize_with = "der_evm_storage"
    )]
    evm_storage: Vec<(U256, Option<SlotChange>)>,

    evm_latest_block_hashes: Option<LatestBlockHashes>,

    /// All unparsed diff goes here.
    pub unparsed: UnparsedStateDiff,
}

pub(crate) fn compress_state(pre_state: PreState, post_state: PostState) -> StatefulStateDiff {
    use compression::{
        compress_one_best_strategy, compress_one_code_hash, compress_two_best_strategy,
        compress_two_code_hash,
    };

    //  Compute diff for all evm::account_prefork2(address): balance, nonce, code_hash
    let mut changed_evm_accounts_prefork2 = BTreeMap::new();
    for (address, new_info) in post_state.evm_accounts_prefork2 {
        let Some(new_info) = new_info else {
            // TODO if acc info was deleted
            continue;
        };

        let prev_info = pre_state.evm_accounts_prefork2.get(&address);
        let acc_change = if let Some(Some(prev_info)) = prev_info {
            AccountChange {
                balance: compress_two_best_strategy(prev_info.balance, new_info.balance),
                nonce: compress_two_best_strategy(
                    U256::from(prev_info.nonce),
                    U256::from(new_info.nonce),
                ),
                code_hash: compress_two_code_hash(prev_info.code_hash, new_info.code_hash),
            }
        } else {
            AccountChange {
                balance: compress_one_best_strategy(new_info.balance),
                nonce: compress_one_best_strategy(U256::from(new_info.nonce)),
                code_hash: compress_one_code_hash(new_info.code_hash),
            }
        };
        changed_evm_accounts_prefork2.insert(address, acc_change);
    }

    // Compute diff for all evm::storage_prefork2(address, key, value)
    let mut changed_evm_storage_prefork2 = BTreeMap::new();
    for (address, new_storage) in post_state.evm_storage_prefork2 {
        let old_storage = pre_state.evm_storage_prefork2.get(&address);
        let mut storage_change = StorageChange {
            storage: Default::default(),
        };
        if let Some(old_storage) = old_storage {
            for (key, new_value) in new_storage {
                let Some(new_value) = new_value else {
                    // if storage(address, key, value) was deleted
                    storage_change.storage.insert(key, None);
                    continue;
                };
                let prev_value = old_storage.get(&key);
                let slot_change = if let Some(&Some(prev_value)) = prev_value {
                    compress_two_best_strategy(prev_value, new_value)
                } else {
                    compress_one_best_strategy(new_value)
                };
                storage_change.storage.insert(key, Some(slot_change));
            }
        } else {
            for (key, new_value) in new_storage {
                let Some(new_value) = new_value else {
                    // if storage(address, key, value) was deleted
                    storage_change.storage.insert(key, None);
                    continue;
                };
                let slot_change = compress_one_best_strategy(new_value);
                storage_change.storage.insert(key, Some(slot_change));
            }
        }

        changed_evm_storage_prefork2.insert(address, storage_change);
    }

    // Compute diff for all evm::account(index): balance, nonce, code_hash
    let mut changed_evm_accounts: Vec<(u64, Option<AccountChange>)> = Vec::new();
    for (index, new_info) in post_state.evm_accounts {
        let prev_info = pre_state.evm_accounts.get(&index);
        match (prev_info, new_info) {
            (None | Some(None), Some(new_info)) => {
                let change = AccountChange {
                    balance: compress_one_best_strategy(new_info.balance),
                    nonce: compress_one_best_strategy(U256::from(new_info.nonce)),
                    code_hash: compress_one_code_hash(new_info.code_hash),
                };
                changed_evm_accounts.push((index, Some(change)));
            }
            (Some(Some(prev_info)), Some(new_info)) => {
                let change = AccountChange {
                    balance: compress_two_best_strategy(prev_info.balance, new_info.balance),
                    nonce: compress_two_best_strategy(
                        U256::from(prev_info.nonce),
                        U256::from(new_info.nonce),
                    ),
                    code_hash: compress_two_code_hash(prev_info.code_hash, new_info.code_hash),
                };
                changed_evm_accounts.push((index, Some(change)));
            }
            (_, None) => {
                changed_evm_accounts.push((index, None));
            }
        }
    }

    // Compute diff for all evm::storage(key, value)
    let mut changed_evm_storage: Vec<(U256, Option<SlotChange>)> = Vec::new();
    for (key, new_value) in post_state.evm_storage {
        let old_value = pre_state.evm_storage.get(&key);
        match (old_value, new_value) {
            (None | Some(None), Some(new_value)) => {
                let slot_change = compress_one_best_strategy(new_value);
                changed_evm_storage.push((key, Some(slot_change)));
            }
            (Some(Some(old_value)), Some(new_value)) => {
                let slot_change = compress_two_best_strategy(*old_value, new_value);
                changed_evm_storage.push((key, Some(slot_change)));
            }
            (_, None) => {
                changed_evm_storage.push((key, None));
            }
        }
    }

    let evm_latest_block_hashes = if post_state.evm_latest_block_hashes.is_empty() {
        None
    } else {
        Some(LatestBlockHashes {
            starting_block_number: post_state.evm_latest_block_hashes[0].0,
            block_hashes: post_state
                .evm_latest_block_hashes
                .into_iter()
                .map(|(_i, hash)| hash)
                .collect(),
        })
    };

    StatefulStateDiff {
        evm_accounts_prefork2: changed_evm_accounts_prefork2,
        evm_storage_prefork2: changed_evm_storage_prefork2,
        evm_accounts: changed_evm_accounts,
        evm_account_address: post_state.evm_account_address,
        evm_account_count: post_state.evm_account_count,
        evm_storage: changed_evm_storage,
        evm_latest_block_hashes,
        unparsed: post_state.unparsed,
    }
}

#[derive(Default, Debug, BorshSerialize, BorshDeserialize, Deserialize, Serialize)]
struct DbAccountInfo {
    #[borsh(serialize_with = "ser_u256", deserialize_with = "der_u256")]
    balance: U256,
    nonce: u64,
    #[borsh(
        serialize_with = "ser_option_b256",
        deserialize_with = "der_option_b256"
    )]
    code_hash: Option<B256>,
}

// borsh serializers and deserializers:

fn ser_u256<W: Write>(x: &U256, writer: &mut W) -> Result<(), Error> {
    let t = x.as_limbs();
    BorshSerialize::serialize(t, writer)
}

fn der_u256<R: Read>(reader: &mut R) -> Result<U256, Error> {
    let t: [u64; 4] = BorshDeserialize::deserialize_reader(reader)?;
    Ok(U256::from_limbs(t))
}

fn ser_vec_b256<W: Write>(xs: &Vec<B256>, writer: &mut W) -> Result<(), Error> {
    let len = u32::try_from(xs.len()).map_err(|_| ErrorKind::InvalidData)?;
    BorshSerialize::serialize(&len, writer)?;
    for x in xs {
        BorshSerialize::serialize(&(x.0), writer)?;
    }
    Ok(())
}

fn der_vec_b256<R: Read>(reader: &mut R) -> Result<Vec<B256>, Error> {
    let len: u32 = BorshDeserialize::deserialize_reader(reader)?;
    let mut res = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let bytes: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
        res.push(B256::from_slice(&bytes));
    }
    Ok(res)
}

fn ser_option_b256<W: Write>(x: &Option<B256>, writer: &mut W) -> Result<(), Error> {
    let t = x.map(|x| x.0);
    BorshSerialize::serialize(&t, writer)
}

fn der_option_b256<R: Read>(reader: &mut R) -> Result<Option<B256>, Error> {
    let s: Option<[u8; 32]> = BorshDeserialize::deserialize_reader(reader)?;
    Ok(s.map(B256::from))
}

fn ser_btree_address<V: BorshSerialize, W: Write>(
    x: &BTreeMap<Address, V>,
    writer: &mut W,
) -> Result<(), Error> {
    let len = u32::try_from(x.len()).map_err(|_| ErrorKind::InvalidData)?;
    BorshSerialize::serialize(&len, writer)?;
    for (key, value) in x {
        BorshSerialize::serialize(&(key.0 .0), writer)?;
        BorshSerialize::serialize(value, writer)?;
    }
    Ok(())
}

fn der_btree_address<V: BorshDeserialize, R: Read>(
    reader: &mut R,
) -> Result<BTreeMap<Address, V>, Error> {
    let len: u32 = BorshDeserialize::deserialize_reader(reader)?;
    let mut v = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let addr: [u8; 20] = BorshDeserialize::deserialize_reader(reader)?;
        let key = Address::from(addr);
        let value = BorshDeserialize::deserialize_reader(reader)?;
        v.push((key, value));
    }
    let res: BTreeMap<_, _> = v.into_iter().collect();
    Ok(res)
}

fn ser_vec_address<W: Write>(xs: &Vec<Address>, writer: &mut W) -> Result<(), Error> {
    let len = u32::try_from(xs.len()).map_err(|_| ErrorKind::InvalidData)?;
    BorshSerialize::serialize(&len, writer)?;
    for x in xs {
        BorshSerialize::serialize(&(x.0 .0), writer)?;
    }
    Ok(())
}

fn der_vec_address<R: Read>(reader: &mut R) -> Result<Vec<Address>, Error> {
    let len: u32 = BorshDeserialize::deserialize_reader(reader)?;
    let mut res = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let bytes: [u8; 20] = BorshDeserialize::deserialize_reader(reader)?;
        res.push(Address::from(bytes));
    }
    Ok(res)
}

fn ser_btree_u256<V: BorshSerialize, W: Write>(
    x: &BTreeMap<U256, V>,
    writer: &mut W,
) -> Result<(), Error> {
    let len = u32::try_from(x.len()).map_err(|_| ErrorKind::InvalidData)?;
    BorshSerialize::serialize(&len, writer)?;
    for (key, value) in x {
        BorshSerialize::serialize(key.as_limbs(), writer)?;
        BorshSerialize::serialize(value, writer)?;
    }
    Ok(())
}

fn der_btree_u256<V: BorshDeserialize, R: Read>(
    reader: &mut R,
) -> Result<BTreeMap<U256, V>, Error> {
    let len: u32 = BorshDeserialize::deserialize_reader(reader)?;
    let mut v = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let limbs = BorshDeserialize::deserialize_reader(reader)?;
        let key = U256::from_limbs(limbs);
        let value = BorshDeserialize::deserialize_reader(reader)?;
        v.push((key, value));
    }
    let res: BTreeMap<_, _> = v.into_iter().collect();
    Ok(res)
}

fn ser_evm_storage<W: Write>(
    evm_storage: &Vec<(U256, Option<SlotChange>)>,
    writer: &mut W,
) -> Result<(), Error> {
    let len = u32::try_from(evm_storage.len()).map_err(|_| ErrorKind::InvalidData)?;
    BorshSerialize::serialize(&len, writer)?;
    for (key, slot_change) in evm_storage {
        BorshSerialize::serialize(key.as_limbs(), writer)?;
        BorshSerialize::serialize(slot_change, writer)?;
    }
    Ok(())
}

fn der_evm_storage<R: Read>(reader: &mut R) -> Result<Vec<(U256, Option<SlotChange>)>, Error> {
    let len: u32 = BorshDeserialize::deserialize_reader(reader)?;
    let mut res = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let limbs = BorshDeserialize::deserialize_reader(reader)?;
        let key = U256::from_limbs(limbs);
        let value = BorshDeserialize::deserialize_reader(reader)?;
        res.push((key, value));
    }
    Ok(res)
}
