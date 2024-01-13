// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc/src/eth/revm_utils.rs

use reth_primitives::{Address, B256, U256};
use reth_rpc_types::state::{AccountOverride, StateOverride};
use reth_rpc_types::{BlockOverrides, CallRequest};
use revm::db::CacheDB;
use revm::primitives::{Bytecode, TransactTo, TxEnv};
use revm::DatabaseRef;

use crate::error::rpc::{EthApiError, EthResult, RpcInvalidTransactionError};
use crate::primitive_types::BlockEnv;

/// Helper type for representing the fees of a [CallRequest]
pub(crate) struct CallFees {
    /// EIP-1559 priority fee
    max_priority_fee_per_gas: Option<U256>,
    /// Unified gas price setting
    ///
    /// Will be the configured `basefee` if unset in the request
    ///
    /// `gasPrice` for legacy,
    /// `maxFeePerGas` for EIP-1559
    gas_price: U256,
    /// Max Fee per Blob gas for EIP-4844 transactions
    // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
    #[allow(dead_code)]
    max_fee_per_blob_gas: Option<U256>,
}

// === impl CallFees ===

impl CallFees {
    /// Ensures the fields of a [CallRequest] are not conflicting.
    ///
    /// If no `gasPrice` or `maxFeePerGas` is set, then the `gas_price` in the returned `gas_price`
    /// will be `0`. See: <https://github.com/ethereum/go-ethereum/blob/2754b197c935ee63101cbbca2752338246384fec/internal/ethapi/transaction_args.go#L242-L255>
    ///
    /// # EIP-4844 transactions
    ///
    /// Blob transactions have an additional fee parameter `maxFeePerBlobGas`.
    /// If the `maxFeePerBlobGas` or `blobVersionedHashes` are set we treat it as an EIP-4844
    /// transaction.
    ///
    /// Note: Due to the `Default` impl of [BlockEnv] (Some(0)) this assumes the `block_blob_fee` is
    /// always `Some`
    fn ensure_fees(
        call_gas_price: Option<U256>,
        call_max_fee: Option<U256>,
        call_priority_fee: Option<U256>,
        block_base_fee: U256,
        blob_versioned_hashes: Option<&[B256]>,
        max_fee_per_blob_gas: Option<U256>,
        block_blob_fee: Option<U256>,
    ) -> EthResult<CallFees> {
        /// Ensures that the transaction's max fee is lower than the priority fee, if any.
        fn ensure_valid_fee_cap(
            max_fee: U256,
            max_priority_fee_per_gas: Option<U256>,
        ) -> EthResult<()> {
            if let Some(max_priority) = max_priority_fee_per_gas {
                if max_priority > max_fee {
                    // Fail early
                    return Err(
                        // `max_priority_fee_per_gas` is greater than the `max_fee_per_gas`
                        RpcInvalidTransactionError::TipAboveFeeCap.into(),
                    );
                }
            }
            Ok(())
        }

        let has_blob_hashes = blob_versioned_hashes
            .as_ref()
            .map(|blobs| !blobs.is_empty())
            .unwrap_or(false);

        match (
            call_gas_price,
            call_max_fee,
            call_priority_fee,
            max_fee_per_blob_gas,
        ) {
            (gas_price, None, None, None) => {
                // either legacy transaction or no fee fields are specified
                // when no fields are specified, set gas price to zero
                let gas_price = gas_price.unwrap_or(U256::ZERO);
                Ok(CallFees {
                    gas_price,
                    max_priority_fee_per_gas: None,
                    max_fee_per_blob_gas: has_blob_hashes.then_some(block_blob_fee).flatten(),
                })
            }
            (None, max_fee_per_gas, max_priority_fee_per_gas, None) => {
                // request for eip-1559 transaction
                let max_fee = max_fee_per_gas.unwrap_or(block_base_fee);
                ensure_valid_fee_cap(max_fee, max_priority_fee_per_gas)?;

                let max_fee_per_blob_gas = has_blob_hashes.then_some(block_blob_fee).flatten();

                Ok(CallFees {
                    gas_price: max_fee,
                    max_priority_fee_per_gas,
                    max_fee_per_blob_gas,
                })
            }
            (None, max_fee_per_gas, max_priority_fee_per_gas, Some(max_fee_per_blob_gas)) => {
                // request for eip-4844 transaction
                let max_fee = max_fee_per_gas.unwrap_or(block_base_fee);
                ensure_valid_fee_cap(max_fee, max_priority_fee_per_gas)?;

                // Ensure blob_hashes are present
                if !has_blob_hashes {
                    // Blob transaction but no blob hashes
                    return Err(RpcInvalidTransactionError::BlobTransactionMissingBlobHashes.into());
                }

                Ok(CallFees {
                    gas_price: max_fee,
                    max_priority_fee_per_gas,
                    max_fee_per_blob_gas: Some(max_fee_per_blob_gas),
                })
            }
            _ => {
                // this fallback covers incompatible combinations of fields
                Err(EthApiError::ConflictingFeeFieldsInRequest)
            }
        }
    }
}

// https://github.com/paradigmxyz/reth/blob/d8677b4146f77c7c82d659c59b79b38caca78778/crates/rpc/rpc/src/eth/revm_utils.rs#L201
pub(crate) fn prepare_call_env<DB>(
    block_env: &mut BlockEnv,
    request: CallRequest,
    db: &mut CacheDB<DB>,
    block_overrides: Option<Box<BlockOverrides>>,
    state_overrides: Option<StateOverride>,
) -> EthResult<TxEnv>
where
    DB: DatabaseRef,
    EthApiError: From<<DB as DatabaseRef>::Error>,
{
    let CallRequest {
        from,
        to,
        mut gas_price,
        mut max_fee_per_gas,
        mut max_priority_fee_per_gas,
        gas,
        value,
        input,
        nonce,
        access_list,
        chain_id,
        ..
    } = request;

    // apply state overrides
    if let Some(state_overrides) = state_overrides {
        apply_state_overrides(state_overrides, db)?;
    }

    // apply block overrides
    if let Some(mut block_overrides) = block_overrides {
        if let Some(block_hashes) = block_overrides.block_hash.take() {
            // override block hashes
            db.block_hashes.extend(
                block_hashes
                    .into_iter()
                    .map(|(num, hash)| (U256::from(num), hash)),
            )
        }
        apply_block_overrides(*block_overrides, block_env);
    }

    // TODO: write hardhat and unit tests for this
    if max_fee_per_gas == Some(U256::ZERO) {
        max_fee_per_gas = None;
    }
    if gas_price == Some(U256::ZERO) {
        gas_price = None;
    }
    if max_priority_fee_per_gas == Some(U256::ZERO) {
        max_priority_fee_per_gas = None;
    }

    let CallFees {
        max_priority_fee_per_gas,
        gas_price,
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        max_fee_per_blob_gas: _,
    } = CallFees::ensure_fees(
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        U256::from(block_env.basefee),
        // EIP-4844 related fields
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        None,
        None,
        None,
    )?;

    let gas_limit = gas.unwrap_or(U256::from(block_env.gas_limit.min(u64::MAX)));

    let env = TxEnv {
        gas_limit: gas_limit
            .try_into()
            .map_err(|_| RpcInvalidTransactionError::GasUintOverflow)?,
        nonce: nonce
            .map(|n| {
                n.try_into()
                    .map_err(|_| RpcInvalidTransactionError::NonceTooHigh)
            })
            .transpose()?,
        caller: from.unwrap_or_default(),
        gas_price,
        gas_priority_fee: max_priority_fee_per_gas,
        transact_to: to.map(TransactTo::Call).unwrap_or_else(TransactTo::create),
        value: value.unwrap_or_default(),
        data: input.try_into_unique_input()?.unwrap_or_default(),
        chain_id: chain_id.map(|c| c.to::<u64>()),
        access_list: access_list
            .map(reth_rpc_types::AccessList::into_flattened)
            .unwrap_or_default(),
        // EIP-4844 related fields
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        blob_hashes: vec![],
        max_fee_per_blob_gas: None,
    };

    Ok(env)
}

/// Applies the given block overrides to the env
fn apply_block_overrides(overrides: BlockOverrides, env: &mut BlockEnv) {
    let BlockOverrides {
        number,
        difficulty,
        time,
        gas_limit,
        coinbase,
        random,
        base_fee,
        block_hash: _,
    } = overrides;

    if let Some(number) = number {
        env.number = number.to::<u64>();
    }
    // if let Some(difficulty) = difficulty {
    //     env.difficulty = difficulty;
    // }
    if let Some(time) = time {
        env.timestamp = time.to::<u64>();
    }
    if let Some(gas_limit) = gas_limit {
        env.gas_limit = gas_limit.to::<u64>();
    }
    if let Some(coinbase) = coinbase {
        env.coinbase = coinbase;
    }
    if let Some(random) = random {
        env.prevrandao = random;
    }
    if let Some(base_fee) = base_fee {
        env.basefee = base_fee.to::<u64>();
    }
}

/// Applies the given state overrides (a set of [AccountOverride]) to the [CacheDB].
fn apply_state_overrides<DB>(overrides: StateOverride, db: &mut CacheDB<DB>) -> EthResult<()>
where
    DB: DatabaseRef,
    EthApiError: From<<DB as DatabaseRef>::Error>,
{
    for (account, account_overrides) in overrides {
        apply_account_override(account, account_overrides, db)?;
    }
    Ok(())
}

/// Applies a single [AccountOverride] to the [CacheDB].
fn apply_account_override<DB>(
    account: Address,
    account_override: AccountOverride,
    db: &mut CacheDB<DB>,
) -> EthResult<()>
where
    DB: DatabaseRef,
    EthApiError: From<<DB as DatabaseRef>::Error>,
{
    // we need to fetch the account via the `DatabaseRef` to not update the state of the account,
    // which is modified via `Database::basic_ref`
    let mut account_info = DatabaseRef::basic_ref(db, account)?.unwrap_or_default();

    if let Some(nonce) = account_override.nonce {
        account_info.nonce = nonce.to();
    }
    if let Some(code) = account_override.code {
        account_info.code = Some(Bytecode::new_raw(code));
    }
    if let Some(balance) = account_override.balance {
        account_info.balance = balance;
    }

    db.insert_account_info(account, account_info);

    // We ensure that not both state and state_diff are set.
    // If state is set, we must mark the account as "NewlyCreated", so that the old storage
    // isn't read from
    match (account_override.state, account_override.state_diff) {
        (Some(_), Some(_)) => return Err(EthApiError::BothStateAndStateDiffInOverride(account)),
        (None, None) => {
            // nothing to do
        }
        (Some(new_account_state), None) => {
            db.replace_account_storage(
                account,
                new_account_state
                    .into_iter()
                    .map(|(slot, value)| (U256::from_be_bytes(slot.0), value))
                    .collect(),
            )?;
        }
        (None, Some(account_state_diff)) => {
            for (slot, value) in account_state_diff {
                db.insert_account_storage(account, U256::from_be_bytes(slot.0), value)?;
            }
        }
    };

    Ok(())
}
