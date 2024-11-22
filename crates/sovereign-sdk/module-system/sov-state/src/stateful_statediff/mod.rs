pub mod compression;

use std::collections::BTreeMap;
use std::io::{Error, ErrorKind, Write};

use alloy_primitives::{Address, B256, U256};
// use alloy_primitives::{address, keccak256, Address, BlockNumber, Bloom, Bytes, B256, U256};
// use borsh::io::{Error, Write};
use borsh::BorshSerialize;
use compression::{CodeHashChange, SlotChange};
use serde::{Deserialize, Serialize};
use sov_modules_core::{CacheKey, CacheValue};

pub(crate) struct PreState {
    evm_accounts: BTreeMap<Address, Option<DbAccountInfo>>,
    evm_storage: BTreeMap<Address, BTreeMap<U256, Option<U256>>>,
}

pub(crate) fn build_pre_state(ordered_reads: Vec<(CacheKey, Option<CacheValue>)>) -> PreState {
    // We need the first values we read. So we traverse from the beginning.
    // We are only interested in keys -> values only when we see them the first time.
    // And we need only Evm accounts and storage, because that's the only
    // thing we need to compress with zksync algorithms.
    let mut evm_accounts: BTreeMap<Address, Option<DbAccountInfo>> = BTreeMap::new();
    let mut evm_storage: BTreeMap<Address, _> = BTreeMap::new();

    for (k, v) in ordered_reads {
        let (key, value) = (k.key, v.map(|v| v.value));
        match &key[..6] {
            _account @ b"Evm/a/" => {
                let address: Address = bcs::from_bytes(&key[6..]).unwrap();
                evm_accounts.entry(address).or_insert_with(|| {
                    let info: Option<DbAccountInfo> =
                        value.as_ref().map(|v| bcs::from_bytes(v).unwrap());
                    info
                });
            }
            _storage @ b"Evm/s/" => {
                let address = Address::from_slice(&key[6..(6 + 20)]);
                let storage_key: U256 = bcs::from_bytes(&key[26..]).unwrap();

                let account_storage: &mut BTreeMap<U256, Option<U256>> =
                    evm_storage.entry(address).or_default();

                account_storage.entry(storage_key).or_insert_with(|| {
                    let storage_value: Option<U256> =
                        value.as_ref().map(|v| bcs::from_bytes(v).unwrap());
                    storage_value
                });
            }
            _ => {}
        }
    }
    PreState {
        evm_accounts,
        evm_storage,
    }
}

pub(crate) struct PostState {
    evm_accounts: BTreeMap<Address, Option<DbAccountInfo>>,
    evm_storage: BTreeMap<Address, BTreeMap<U256, Option<U256>>>,
    // TODO other typed key->values
    untyped: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

pub(crate) fn build_post_state(ordered_writes: &[(CacheKey, Option<CacheValue>)]) -> PostState {
    // We need the last values we write. So we traverse from the end.
    let mut evm_accounts: BTreeMap<Address, Option<DbAccountInfo>> = BTreeMap::new();
    let mut evm_storage: BTreeMap<Address, _> = BTreeMap::new();
    let mut untyped = Vec::new();

    for (k, v) in ordered_writes.iter().rev() {
        let (key, value) = (k.key.clone(), v.clone().map(|v| v.value));
        match &key[..6] {
            _account @ b"Evm/a/" => {
                // Only the first key -> value
                let address: Address = bcs::from_bytes(&key[6..]).unwrap();
                evm_accounts.entry(address).or_insert_with(|| {
                    let info: Option<DbAccountInfo> =
                        value.as_ref().map(|v| bcs::from_bytes(v).unwrap());
                    info
                });
            }
            _storage @ b"Evm/s/" => {
                // Only the first key -> value
                let address = Address::from_slice(&key[6..(6 + 20)]);
                let storage_key: U256 = bcs::from_bytes(&key[26..]).unwrap();

                let account_storage: &mut BTreeMap<U256, Option<U256>> =
                    evm_storage.entry(address).or_default();

                account_storage.entry(storage_key).or_insert_with(|| {
                    let storage_value: Option<U256> =
                        value.as_ref().map(|v| bcs::from_bytes(v).unwrap());
                    storage_value
                });
            }
            _ => {
                let key_bytes = (*key).clone();
                let value_bytes = value.map(|v| (*v).clone());

                untyped.push((key_bytes, value_bytes));
            }
        }
    }
    PostState {
        evm_accounts,
        evm_storage,
        untyped,
    }
}

#[derive(BorshSerialize, Debug)]
pub struct AccountChange {
    pub balance: SlotChange,
    pub nonce: SlotChange,
    pub code_hash: CodeHashChange,
}

#[derive(BorshSerialize, Debug)]
pub struct StorageChange {
    #[borsh(serialize_with = "borsh_ser_btree_u256")]
    pub storage: BTreeMap<U256, Option<SlotChange>>,
}

#[derive(BorshSerialize, Debug)]
pub struct StatefulStateDiff {
    #[borsh(serialize_with = "borsh_ser_btree_address")]
    evm_accounts: BTreeMap<Address, AccountChange>,
    #[borsh(serialize_with = "borsh_ser_btree_address")]
    evm_storage: BTreeMap<Address, StorageChange>,
    // TODO other typed key->values
    untyped: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

pub(crate) fn compress_state(pre_state: PreState, post_state: PostState) -> StatefulStateDiff {
    use compression::{
        compress_one_best_strategy, compress_one_code_hash, compress_two_best_strategy,
        compress_two_code_hash,
    };

    //  Compute diff for all evm::account(address): balance, nonce, code_hash
    let mut changed_evm_accounts = BTreeMap::new();
    for (address, new_info) in post_state.evm_accounts {
        let Some(new_info) = new_info else {
            // TODO if acc info was deleted
            continue;
        };

        let prev_info = pre_state.evm_accounts.get(&address);
        let acc_change = if let Some(Some(prev_info)) = prev_info {
            AccountChange {
                balance: compress_two_best_strategy(prev_info.balance, new_info.balance),
                nonce: compress_two_best_strategy(prev_info.balance, U256::from(new_info.nonce)),
                code_hash: compress_two_code_hash(prev_info.code_hash, new_info.code_hash),
            }
        } else {
            AccountChange {
                balance: compress_one_best_strategy(new_info.balance),
                nonce: compress_one_best_strategy(U256::from(new_info.nonce)),
                code_hash: compress_one_code_hash(new_info.code_hash),
            }
        };
        changed_evm_accounts.insert(address, acc_change);
    }

    // Compute diff for all evm::storage(address, key, value)
    let mut changed_evm_storage = BTreeMap::new();
    for (address, new_storage) in post_state.evm_storage {
        let old_storage = pre_state.evm_storage.get(&address);
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

        changed_evm_storage.insert(address, storage_change);
    }

    StatefulStateDiff {
        evm_accounts: changed_evm_accounts,
        evm_storage: changed_evm_storage,
        untyped: post_state.untyped,
    }
}

#[derive(Default, BorshSerialize, Deserialize, Serialize, Debug, Clone)]
struct DbAccountInfo {
    #[borsh(serialize_with = "borsh_ser_u256")]
    balance: U256,
    nonce: u64,
    #[borsh(serialize_with = "borsh_ser_option_b256")]
    code_hash: Option<B256>,
}

// borsh serializers:

// fn borsh_ser_address<W: Write>(x: &Address, writer: &mut W) -> Result<(), Error> {
//     let t = x.0 .0;
//     BorshSerialize::serialize(&t, writer)
// }

fn borsh_ser_u256<W: Write>(x: &U256, writer: &mut W) -> Result<(), Error> {
    let t = x.to_be_bytes::<32>();
    BorshSerialize::serialize(&t, writer)
}

// fn borsh_ser_option_u256<W: Write>(x: &Option<U256>, writer: &mut W) -> Result<(), Error> {
//     let t = x.map(|x| x.to_be_bytes::<32>());
//     BorshSerialize::serialize(&t, writer)
// }

// fn borsh_ser_b256<W: Write>(x: &B256, writer: &mut W) -> Result<(), Error> {
//     let t = x.0;
//     BorshSerialize::serialize(&t, writer)
// }

// fn borsh_ser_vec_b256<W: Write>(x: &Vec<B256>, writer: &mut W) -> Result<(), Error> {
//     let t: Vec<_> = x.into_iter().map(|x| x.0).collect();
//     BorshSerialize::serialize(&t, writer)
// }

fn borsh_ser_option_b256<W: Write>(x: &Option<B256>, writer: &mut W) -> Result<(), Error> {
    let t = x.map(|x| x.0);
    BorshSerialize::serialize(&t, writer)
}

// fn borsh_ser_bytes<W: Write>(x: &Bytes, writer: &mut W) -> Result<(), Error> {
//     let t = &x.0;
//     BorshSerialize::serialize(&t, writer)
// }

// fn borsh_ser_bloom<W: Write>(x: &Bloom, writer: &mut W) -> Result<(), Error> {
//     let t = x.0 .0;
//     BorshSerialize::serialize(&t, writer)
// }

fn borsh_ser_btree_address<V: BorshSerialize, W: Write>(
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

fn borsh_ser_btree_u256<V: BorshSerialize, W: Write>(
    x: &BTreeMap<U256, V>,
    writer: &mut W,
) -> Result<(), Error> {
    let len = u32::try_from(x.len()).map_err(|_| ErrorKind::InvalidData)?;
    BorshSerialize::serialize(&len, writer)?;
    for (key, value) in x {
        BorshSerialize::serialize(key.as_le_slice(), writer)?;
        BorshSerialize::serialize(value, writer)?;
    }
    Ok(())
}
