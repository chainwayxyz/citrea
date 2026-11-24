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
mod trace_limit;
mod tracing_utils;

use sov_modules_api::{StateMapAccessor, WorkingSet};
use sov_state::storage::{NativeStorage, StateCodec, StorageKey};
pub(crate) use trace_limit::TraceMemoryUsage;
pub use trace_limit::{mb_to_bytes, trace_memory_limit_exceeded};
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
/// See <https://github.com/alloy-rs/evm/blob/v0.39.0/crates/evm/src/overrides.rs#L125-L194>.
pub(crate) fn apply_account_override<C: sov_modules_api::Context>(
    account: Address,
    account_override: AccountOverride,
    db: &mut EvmDb<C>,
) -> EthResult<()> {
    let mut account_info = db.basic(account)?.unwrap_or_default();

    if let Some(nonce) = account_override.nonce {
        account_info.nonce = nonce;
    }
    if let Some(code) = account_override.code {
        let code_hash = keccak256(&code);
        let evm = Evm::<C>::default();
        evm.offchain_code.set(
            &code_hash,
            &revm::bytecode::Bytecode::new_raw_checked(code)
                .map_err(|err| EthApiError::InvalidBytecode(err.to_string()))?,
            &mut db.working_set.offchain_state(),
        );
        account_info.code_hash = code_hash;
    }
    if let Some(balance) = account_override.balance {
        account_info.balance = balance;
    }

    match (account_override.state, account_override.state_diff) {
        (Some(_), Some(_)) => return Err(EthApiError::BothStateAndStateDiffInOverride(account)),
        // `state` replaces the whole storage, so the replacement takes precedence over the working
        // set even when the requested slot is absent from the replacement.
        (Some(state), None) => db.replace_account_storage(account, state),
        (None, Some(diff)) => db.override_set_account_storage(&account, diff),
        (None, None) => {}
    }

    db.override_account(&account, account_info.into());

    Ok(())
}

/// Applies [`BlockOverrides`] to the block environment and database.
pub(crate) fn apply_block_overrides<C: sov_modules_api::Context>(
    block_env: &mut BlockEnv,
    block_overrides: BlockOverrides,
    db: &mut EvmDb<C>,
    canonical_block: u64,
) {
    let BlockOverrides {
        number,
        time,
        gas_limit,
        coinbase,
        random,
        base_fee,
        block_hash,
        difficulty: _,
    } = block_overrides;
    db.override_block_hashes(
        block_hash.unwrap_or_default(),
        number.map(|_| block_env.number),
        canonical_block,
    );
    if let Some(number) = number {
        block_env.number = number.saturating_to();
    }
    if let Some(time) = time {
        block_env.timestamp = time;
    }
    if let Some(gas_limit) = gas_limit {
        // A block override may only *lower* the block gas limit, never raise it, so the `GASLIMIT`
        // opcode a call sees is at most the chain's real value. This clamp is also the safety net
        // for a `gas_cap` of 0 ("keep the block gas limit"): there the transaction gas is bounded
        // by `block_env.gas_limit` (see `create_txn_env`), so without the clamp a `u64::MAX`
        // override would let one call expand EVM memory without bound (e.g. an `MSTORE` at a
        // multi-GiB offset). With a non-zero cap the transaction gas is bounded by the cap
        // regardless, so the override only affects the opcode.
        block_env.gas_limit = block_env.gas_limit.min(gas_limit);
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
