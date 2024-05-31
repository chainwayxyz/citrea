// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc/src/eth/revm_utils.rs

use std::cmp::min;

use reth_primitives::{TxKind, B256, U256};
use reth_rpc::eth::error::{EthApiError, EthResult, RpcInvalidTransactionError};
use reth_rpc_types::TransactionRequest;
use revm::primitives::{TransactTo, TxEnv};

use crate::caller_gas_allowance;
use crate::primitive_types::BlockEnv;

/// Helper type for representing the fees of a [TransactionRequest]
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
    /// Ensures the fields of a [TransactionRequest] are not conflicting.
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
        /// Get the effective gas price of a transaction as specfified in EIP-1559 with relevant
        /// checks.
        fn get_effective_gas_price(
            max_fee_per_gas: Option<U256>,
            max_priority_fee_per_gas: Option<U256>,
            block_base_fee: U256,
        ) -> EthResult<U256> {
            match max_fee_per_gas {
                Some(max_fee) => {
                    if max_fee < block_base_fee {
                        // `base_fee_per_gas` is greater than the `max_fee_per_gas`
                        return Err(RpcInvalidTransactionError::FeeCapTooLow.into());
                    }
                    if max_fee < max_priority_fee_per_gas.unwrap_or(U256::ZERO) {
                        return Err(
                            // `max_priority_fee_per_gas` is greater than the `max_fee_per_gas`
                            RpcInvalidTransactionError::TipAboveFeeCap.into(),
                        );
                    }
                    Ok(min(
                        max_fee,
                        block_base_fee
                            .checked_add(max_priority_fee_per_gas.unwrap_or(U256::ZERO))
                            .ok_or_else(|| {
                                EthApiError::from(RpcInvalidTransactionError::TipVeryHigh)
                            })?,
                    ))
                }
                None => Ok(block_base_fee
                    .checked_add(max_priority_fee_per_gas.unwrap_or(U256::ZERO))
                    .ok_or_else(|| EthApiError::from(RpcInvalidTransactionError::TipVeryHigh))?),
            }
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
                let effective_gas_price = get_effective_gas_price(
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    block_base_fee,
                )?;

                let max_fee_per_blob_gas = has_blob_hashes.then_some(block_blob_fee).flatten();

                Ok(CallFees {
                    gas_price: effective_gas_price,
                    max_priority_fee_per_gas,
                    max_fee_per_blob_gas,
                })
            }
            (None, max_fee_per_gas, max_priority_fee_per_gas, Some(max_fee_per_blob_gas)) => {
                // request for eip-4844 transaction
                let effective_gas_price = get_effective_gas_price(
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    block_base_fee,
                )?;

                // Ensure blob_hashes are present
                if !has_blob_hashes {
                    // Blob transaction but no blob hashes
                    return Err(RpcInvalidTransactionError::BlobTransactionMissingBlobHashes.into());
                }

                Ok(CallFees {
                    gas_price: effective_gas_price,
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
// if from_balance is None, gas capping will not be applied
pub(crate) fn prepare_call_env(
    block_env: &BlockEnv,
    request: TransactionRequest,
    cap_to_balance: Option<U256>,
) -> EthResult<TxEnv> {
    let TransactionRequest {
        from,
        to,
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas,
        value,
        input,
        nonce,
        access_list,
        chain_id,
        ..
    } = request;
    let mut gas_price = gas_price.map(U256::from);
    let mut max_fee_per_gas = max_fee_per_gas.map(U256::from);
    let mut max_priority_fee_per_gas = max_priority_fee_per_gas.map(U256::from);
    let gas = gas.map(U256::from);

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

    let mut gas_limit = U256::from(block_env.gas_limit);

    if let Some(request_gas_limit) = gas {
        // gas limit is set by user in the request
        // we must make sure it does not exceed the block gas limit
        // otherwise there is a DoS vector
        gas_limit = min(request_gas_limit, gas_limit);
    } else if cap_to_balance.is_some() && gas_price > U256::ZERO {
        // cap_to_balance is Some only when called from eth_call and eth_createAccessList
        // we fall in this branch when user set gas price but not gas limit
        // before passing the transaction environment to evm, we must set a gas limit
        // that is capped by the caller's balance
        // but the from address might have a high balance
        // we don't want the gas limit to be more then the block gas limit
        let max_gas_limit = caller_gas_allowance(
            cap_to_balance.unwrap(),
            value.unwrap_or_default(),
            gas_price,
        )?;
        gas_limit = min(gas_limit, max_gas_limit);
    }

    let to = if let Some(kind) = to {
        match kind {
            TxKind::Create => TransactTo::create(),
            TxKind::Call(address) => TransactTo::call(address),
        }
    } else {
        TransactTo::create()
    };

    let env = TxEnv {
        gas_price,
        nonce,
        chain_id,
        gas_limit: gas_limit
            .try_into()
            .map_err(|_| RpcInvalidTransactionError::GasUintOverflow)?,
        caller: from.unwrap_or_default(),
        gas_priority_fee: max_priority_fee_per_gas,
        transact_to: to,
        value: value.unwrap_or_default(),
        data: input.try_into_unique_input()?.unwrap_or_default(),
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

#[cfg(test)]
mod tests {
    use reth_primitives::constants::GWEI_TO_WEI;

    use super::*;

    #[test]
    fn test_eip_1559_fees() {
        let CallFees { gas_price, .. } = CallFees::ensure_fees(
            None,
            Some(U256::from(25 * GWEI_TO_WEI)),
            Some(U256::from(15 * GWEI_TO_WEI)),
            U256::from(15 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        )
        .unwrap();
        assert_eq!(gas_price, U256::from(25 * GWEI_TO_WEI));

        let CallFees { gas_price, .. } = CallFees::ensure_fees(
            None,
            Some(U256::from(25 * GWEI_TO_WEI)),
            Some(U256::from(5 * GWEI_TO_WEI)),
            U256::from(15 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        )
        .unwrap();
        assert_eq!(gas_price, U256::from(20 * GWEI_TO_WEI));

        let CallFees { gas_price, .. } = CallFees::ensure_fees(
            None,
            Some(U256::from(30 * GWEI_TO_WEI)),
            Some(U256::from(30 * GWEI_TO_WEI)),
            U256::from(15 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        )
        .unwrap();
        assert_eq!(gas_price, U256::from(30 * GWEI_TO_WEI));

        let call_fees = CallFees::ensure_fees(
            None,
            Some(U256::from(30 * GWEI_TO_WEI)),
            Some(U256::from(31 * GWEI_TO_WEI)),
            U256::from(15 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        );
        assert!(call_fees.is_err());

        let call_fees = CallFees::ensure_fees(
            None,
            Some(U256::from(5 * GWEI_TO_WEI)),
            Some(U256::from(GWEI_TO_WEI)),
            U256::from(15 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        );
        assert!(call_fees.is_err());

        let call_fees = CallFees::ensure_fees(
            None,
            Some(U256::MAX),
            Some(U256::MAX),
            U256::from(5 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        );
        assert!(call_fees.is_err());
    }
}
