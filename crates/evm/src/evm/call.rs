// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc/src/eth/revm_utils.rs

use std::cmp::min;

use alloy_consensus::TxType;
use alloy_primitives::U256;
use alloy_rpc_types::TransactionRequest;
use reth_rpc_eth_types::error::{EthResult, RpcInvalidTransactionError};
use reth_rpc_eth_types::revm_utils::CallFees;
use revm::context::{BlockEnv, CfgEnv, TxEnv};

use crate::caller_gas_allowance;

pub(crate) fn create_txn_env(
    block_env: &BlockEnv,
    request: TransactionRequest,
    cap_to_balance: Option<U256>,
    nonce_if_req_has_no_nonce: Option<u64>,
    chain_id_to_set: u64,
) -> EthResult<TxEnv> {
    let tx_type = if request.authorization_list.is_some() {
        TxType::Eip7702
    } else if request.sidecar.is_some() || request.max_fee_per_blob_gas.is_some() {
        return Err(RpcInvalidTransactionError::TxTypeNotSupported.into());
    } else if request.max_fee_per_gas.is_some() || request.max_priority_fee_per_gas.is_some() {
        TxType::Eip1559
    } else if request.access_list.is_some() {
        TxType::Eip2930
    } else {
        TxType::Legacy
    } as u8;

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
        authorization_list,
        transaction_type: _transaction_type,
        blob_versioned_hashes,
        ..
    } = request;

    if blob_versioned_hashes.is_some_and(|v| !v.is_empty()) {
        return Err(RpcInvalidTransactionError::TxTypeNotSupported.into());
    }

    let CallFees {
        max_priority_fee_per_gas,
        gas_price,
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        max_fee_per_blob_gas: _,
    } = CallFees::ensure_fees(
        gas_price.map(U256::from),
        max_fee_per_gas.map(U256::from),
        max_priority_fee_per_gas.map(U256::from),
        U256::from(block_env.basefee),
        // EIP-4844 related fields
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        None,
        None,
        None,
    )?;

    // set gas limit initially to block gas limit
    let mut gas_limit = U256::from(block_env.gas_limit);
    let request_gas_limit = gas.map(U256::from);

    if let Some(request_gas_limit) = request_gas_limit {
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

    let gas_priority_fee: Option<u128> = if let Some(gas_priority) = max_priority_fee_per_gas {
        let value: u128 = gas_priority
            .try_into()
            .map_err(|_| RpcInvalidTransactionError::GasUintOverflow)?;
        Some(value)
    } else {
        None
    };

    let caller = from.unwrap_or_default();

    let nonce = if let Some(nonce) = nonce {
        if nonce_if_req_has_no_nonce.is_some() {
            unreachable!("We never pass a nonce to this function if the request has a nonce")
        }
        nonce
    } else {
        nonce_if_req_has_no_nonce.expect("If req has no nonce, we must pass one")
    };

    let chain_id = Some(chain_id.unwrap_or(chain_id_to_set));
    let env = TxEnv {
        tx_type,
        gas_price: gas_price
            .try_into()
            .map_err(|_| RpcInvalidTransactionError::GasUintOverflow)?,
        nonce,
        chain_id,
        gas_limit: gas_limit
            .try_into()
            .map_err(|_| RpcInvalidTransactionError::GasUintOverflow)?,
        caller,
        gas_priority_fee,
        kind: to.unwrap_or_default(),
        value: value.unwrap_or_default(),
        data: input.try_into_unique_input()?.unwrap_or_default(),
        access_list: access_list.unwrap_or_default(),
        authorization_list: authorization_list.unwrap_or_default().to_vec(),

        // EIP-4844 related fields
        // as the `TxEnv` returned from this function is given to plain revm::Evm
        // and as CitreaEvm ignores type3 txs, we can safely ignore these fields
        blob_hashes: vec![],
        max_fee_per_blob_gas: 0,
    };

    Ok(env)
}

// https://github.com/paradigmxyz/reth/blob/d8677b4146f77c7c82d659c59b79b38caca78778/crates/rpc/rpc/src/eth/revm_utils.rs#L201
// if from_balance is None, gas capping will not be applied
pub(crate) fn prepare_call_env(
    block_env: &BlockEnv,
    cfg_env: &mut CfgEnv,
    mut request: TransactionRequest,
    cap_to_balance: U256,
    nonce: u64,
    chain_id_to_set: u64,
) -> EthResult<TxEnv> {
    // we want to disable this in eth_call, since this is common practice used by other node
    // impls and providers <https://github.com/foundry-rs/foundry/issues/4388>
    cfg_env.disable_block_gas_limit = true;

    // Disabled because eth_call is sometimes used with eoa senders
    // See <https://github.com/paradigmxyz/reth/issues/1959>
    cfg_env.disable_eip3607 = true;

    // The basefee should be ignored for eth_call
    // See:
    // <https://github.com/ethereum/go-ethereum/blob/ee8e83fa5f6cb261dad2ed0a7bbcde4930c41e6c/internal/ethapi/api.go#L985>
    cfg_env.disable_base_fee = true;

    // set nonce to None so that the correct nonce is chosen by the EVM
    request.nonce = None;

    // TODO: write hardhat and unit tests for this
    if request.max_fee_per_gas == Some(0) {
        request.max_fee_per_gas = None;
    }
    if request.gas_price == Some(0) {
        request.gas_price = None;
    }
    if request.max_priority_fee_per_gas == Some(0) {
        request.max_priority_fee_per_gas = None;
    }

    create_txn_env(
        block_env,
        request.clone(),
        Some(cap_to_balance),
        Some(nonce),
        chain_id_to_set,
    )
}

#[cfg(test)]
mod tests {
    use alloy_consensus::constants::GWEI_TO_WEI;

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
