use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{Address, Bytes};
use alloy_rpc_types::state::{AccountOverride, StateOverride};
use alloy_rpc_types::{BlockOverrides, EIP1186AccountProofResponse, EIP1186StorageProof};
use alloy_serde::JsonStorageKey;
pub use filter::*;
pub use log_utils::*;
use reth_rpc_eth_types::revm_utils::apply_block_overrides as apply_reth_block_overrides;
use reth_rpc_eth_types::{EthApiError, EthResult};
use revm::context::BlockEnv;
use revm::state::Bytecode;
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

use crate::db::{EvmDb, RpcAccountOverride};
use crate::Evm;

/// Applies state overrides to the simulation database.
///
/// Citrea mirrors Reth's RPC storage semantics. It serves storage replacements from the simulation
/// database because its state layout stores slots independently of the account record.
/// [Reth v1.3.7 `CacheDB` overrides](https://github.com/paradigmxyz/reth/blob/ed7da87da4de340a437bf46f39a7e1397ac82065/crates/rpc/rpc-eth-types/src/revm_utils.rs#L275-L340)
pub(crate) fn apply_state_overrides<C: sov_modules_api::Context>(
    state_overrides: StateOverride,
    db: &mut EvmDb<C>,
) -> EthResult<()> {
    for (address, account_overrides) in state_overrides {
        apply_account_override(address, account_overrides, db)?;
    }

    Ok(())
}

fn apply_account_override<C: sov_modules_api::Context>(
    account: Address,
    account_override: AccountOverride,
    db: &mut EvmDb<C>,
) -> EthResult<()> {
    let mut account_info = db.basic(account)?.unwrap_or_default();
    let code = account_override
        .code
        .map(Bytecode::new_raw_checked)
        .transpose()
        .map_err(|err| EthApiError::InvalidBytecode(err.to_string()))?;
    let (storage, replace_storage) = match (account_override.state, account_override.state_diff) {
        (Some(_), Some(_)) => return Err(EthApiError::BothStateAndStateDiffInOverride(account)),
        (Some(state), None) => (state, true),
        (None, diff) => (diff.unwrap_or_default(), false),
    };

    if let Some(nonce) = account_override.nonce {
        account_info.nonce = nonce;
    }
    if let Some(code) = code {
        // Hash the replacement bytes, as in Alloy's override helper.
        // <https://github.com/alloy-rs/evm/blob/v0.39.0/crates/evm/src/overrides.rs#L134-L142>
        account_info.code_hash = code.hash_slow();
        // A default account carries empty bytecode. Clear it so revm loads the override by hash.
        account_info.code = None;
        db.override_code(account_info.code_hash, code);
    }
    if let Some(balance) = account_override.balance {
        account_info.balance = balance;
    }

    db.override_account(
        account,
        RpcAccountOverride {
            info: account_info,
            storage,
            replace_storage,
        },
    );

    Ok(())
}

/// Applies Reth's block overrides with Citrea's block gas limit ceiling.
/// [Reth v1.3.7 `apply_block_overrides`](https://github.com/paradigmxyz/reth/blob/ed7da87da4de340a437bf46f39a7e1397ac82065/crates/rpc/rpc-eth-types/src/revm_utils.rs#L196-L261)
pub(crate) fn apply_block_overrides<C: sov_modules_api::Context>(
    block_env: &mut BlockEnv,
    mut block_overrides: BlockOverrides,
    db: &mut EvmDb<C>,
    canonical_block: u64,
) {
    if block_overrides.number.is_some() {
        db.set_block_hash_base(canonical_block);
    }
    if let Some(gas_limit) = &mut block_overrides.gas_limit {
        // A zero RPC gas cap uses the block gas limit to bound transaction gas. Clamping the
        // override keeps that bound in place and caps the value reported by GASLIMIT.
        *gas_limit = (*gas_limit).min(block_env.gas_limit);
    }
    apply_reth_block_overrides(block_overrides, db, block_env);
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
