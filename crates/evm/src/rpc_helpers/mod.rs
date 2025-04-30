use std::collections::HashMap;

use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{keccak256, Address, Bytes};
use alloy_rpc_types::state::AccountOverride;
use alloy_rpc_types::{BlockOverrides, EIP1186AccountProofResponse, EIP1186StorageProof};
use alloy_serde::JsonStorageKey;
pub use filter::*;
pub use log_utils::*;
use reth_rpc_eth_types::{EthApiError, EthResult};
use revm::context::BlockEnv;
use revm::Database;

mod filter;
mod log_utils;
mod tracing_utils;

use sov_modules_api::{StateMapAccessor, WorkingSet};
use sov_state::storage::{NativeStorage, StateCodec, StorageKey};
pub(crate) use tracing_utils::*;

use crate::db::EvmDb;
use crate::Evm;

/// Applies all instances [`AccountOverride`] to the [`EvmDb`].
pub(crate) fn apply_state_overrides<C: sov_modules_api::Context>(
    state_overrides: HashMap<Address, AccountOverride, alloy_primitives::map::FbBuildHasher<20>>,
    db: &mut EvmDb<C>,
) -> EthResult<()> {
    for (address, account_overrides) in state_overrides {
        apply_account_override(address, account_overrides, db)?;
    }

    Ok(())
}

/// Applies a single [`AccountOverride`] to the [`EvmDb`].
pub(crate) fn apply_account_override<C: sov_modules_api::Context>(
    account: Address,
    account_override: AccountOverride,
    db: &mut EvmDb<C>,
) -> EthResult<()> {
    // we need to fetch the account via the `DatabaseRef` to not update the state of the account,
    // which is modified via `Database::basic_ref`
    let mut account_info = db.basic(account)?.unwrap_or_default();

    if let Some(nonce) = account_override.nonce {
        account_info.nonce = nonce;
    }
    if let Some(code) = account_override.code {
        account_info.code_hash = keccak256(code);
    }
    if let Some(balance) = account_override.balance {
        account_info.balance = balance;
    }

    db.override_account(&account, account_info.into());

    // We ensure that not both state and state_diff are set.
    // If state is set, we must mark the account as "NewlyCreated", so that the old storage
    // isn't read from
    match (account_override.state, account_override.state_diff) {
        (Some(_), Some(_)) => return Err(EthApiError::BothStateAndStateDiffInOverride(account)),
        (None, None) => {
            // nothing to do
        }
        (Some(new_account_state), None) => {
            db.override_set_account_storage(&account, new_account_state);
        }
        (None, Some(account_state_diff)) => {
            db.override_set_account_storage(&account, account_state_diff);
        }
    };

    Ok(())
}

/// Applies all instances of [`BlockOverride`] to the [`EvmDb`].
pub(crate) fn apply_block_overrides<C: sov_modules_api::Context>(
    block_env: &mut BlockEnv,
    block_overrides: &mut BlockOverrides,
    db: &mut EvmDb<C>,
) {
    if let Some(block_hashes) = block_overrides.block_hash.take() {
        // override block hashes
        for (num, hash) in block_hashes {
            db.override_block_hash(num, hash);
        }
    }

    let BlockOverrides {
        number,
        time,
        gas_limit,
        coinbase,
        random,
        base_fee,
        block_hash: _,
        difficulty: _,
    } = *block_overrides;
    if let Some(number) = number {
        block_env.number = number.saturating_to();
    }
    if let Some(time) = time {
        block_env.timestamp = time;
    }
    if let Some(gas_limit) = gas_limit {
        block_env.gas_limit = gas_limit;
    }
    if let Some(coinbase) = coinbase {
        block_env.beneficiary = coinbase;
    }
    if let Some(random) = random {
        block_env.prevrandao = Some(random);
    }
    if let Some(base_fee) = base_fee {
        block_env.basefee = base_fee.saturating_to();
    }
}

/// Returns zkproof by EIP-1186 (eth_getProof).
// `Evm`` and `working_set`` must be rewind to the specified `version``.
pub fn generate_eth_proof<C: sov_modules_api::Context>(
    evm: &Evm<C>,
    address: Address,
    keys: Vec<JsonStorageKey>,
    version: u64,
    working_set: &mut WorkingSet<C::Storage>,
) -> EIP1186AccountProofResponse
where
    C::Storage: NativeStorage,
{
    let root_hash = working_set
        .get_root_hash(version)
        .expect("Root hash must exist for all blocks");

    let account = evm.account_info(&address, working_set).unwrap_or_default();
    let balance = account.balance;
    let nonce = account.nonce;
    let code_hash = account.code_hash.unwrap_or(KECCAK_EMPTY);

    fn generate_account_proof<C>(
        evm: &Evm<C>,
        account: &Address,
        version: u64,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Vec<Bytes>
    where
        C: sov_modules_api::Context,
        C::Storage: NativeStorage,
    {
        let index_key = StorageKey::new(
            evm.account_idxs.prefix(),
            account,
            evm.account_idxs.codec().key_codec(),
        );
        let index_proof = working_set.get_with_proof(index_key, version);
        let index_proof_exists = index_proof.value.is_some();
        let index_proof = borsh::to_vec(&index_proof.proof).expect("Serialization shouldn't fail");
        let index_proof = Bytes::from(index_proof);

        if index_proof_exists {
            // we have to generate another proof for idx -> account
            let index = evm
                .account_idxs
                .get(account, working_set)
                .expect("Account index exists");
            let index_bytes = Bytes::from_iter(index.to_le_bytes());

            let account_key = StorageKey::new(
                evm.accounts.prefix(),
                &index,
                evm.accounts.codec().key_codec(),
            );

            let account_proof = working_set.get_with_proof(account_key, version);
            let account_exists = if account_proof.value.is_some() {
                Bytes::from("y")
            } else {
                Bytes::from("n")
            };
            let account_proof =
                borsh::to_vec(&account_proof.proof).expect("Serialization shouldn't fail");
            let account_proof = Bytes::from(account_proof);
            vec![index_proof, index_bytes, account_proof, account_exists]
        } else {
            let index_exists = Bytes::from("n");

            vec![index_proof, index_exists]
        }
    }

    fn generate_storage_proof<C>(
        evm: &Evm<C>,
        account: &Address,
        key: JsonStorageKey,
        version: u64,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> EIP1186StorageProof
    where
        C: sov_modules_api::Context,
        C::Storage: NativeStorage,
    {
        let key_b = key.as_b256().into();
        let kaddr = Evm::<C>::get_storage_address(account, &key_b);
        let storage_key = StorageKey::new(
            evm.storage.prefix(),
            &kaddr,
            evm.storage.codec().key_codec(),
        );
        let value = evm.storage_get(account, &key_b, working_set);
        let proof = working_set.get_with_proof(storage_key, version);
        let value_exists = if proof.value.is_some() {
            Bytes::from("y")
        } else {
            Bytes::from("n")
        };
        let value_proof = borsh::to_vec(&proof.proof).expect("Serialization shouldn't fail");
        let value_proof = Bytes::from(value_proof);
        EIP1186StorageProof {
            key,
            value: value.unwrap_or_default(),
            proof: vec![value_proof, value_exists],
        }
    }

    let account_proof = generate_account_proof(evm, &address, version, working_set);

    let mut storage_proof = vec![];
    for key in keys {
        let proof = generate_storage_proof(evm, &address, key, version, working_set);
        storage_proof.push(proof);
    }

    EIP1186AccountProofResponse {
        address,
        balance,
        nonce,
        code_hash,
        storage_hash: root_hash.into(),
        account_proof,
        storage_proof,
    }
}
