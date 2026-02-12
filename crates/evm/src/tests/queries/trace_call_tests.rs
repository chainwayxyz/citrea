use std::str::FromStr;

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::map::AddressMap;
use alloy_primitives::{Address, TxKind, U256};
use alloy_rpc_types::state::AccountOverride;
use alloy_rpc_types::TransactionRequest;
use alloy_rpc_types_trace::geth::GethDebugTracingCallOptions;

use crate::tests::queries::init_evm_single_block;

/// Regression test for issue #3135
/// debug_traceCall with balance state override and no explicit gas limit
/// should succeed (state overrides must be applied before gas allowance calculation)
#[test]
fn test_debug_trace_call_with_balance_override_no_gas_limit() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let large_value = U256::from_str("999999999999999999999999999999").unwrap();

    // Transaction with a large value transfer but NO explicit gas limit.
    // Without the fix, this fails because create_txn_env → caller_gas_allowance
    // checks the real (low) balance before state overrides are applied.
    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        )),
        value: Some(large_value),
        gas_price: Some(1_000_000_000),
        // NOTE: gas is intentionally omitted to reproduce the issue
        ..Default::default()
    };

    // Without balance override, it should fail
    let result_without_override = evm.debug_trace_call(
        tx_req.clone(),
        Some(BlockNumberOrTag::Latest.into()),
        None,
        &mut working_set,
        &ledger_db,
    );

    assert!(
        result_without_override.is_err(),
        "Should fail with insufficient funds when no balance override is provided"
    );

    // Create state override with sufficient balance
    let mut state_override = AddressMap::default();
    state_override.insert(
        signer.address(),
        AccountOverride {
            balance: Some(U256::from_str("2000000000000000000000000000000").unwrap()),
            ..Default::default()
        },
    );

    let opts = GethDebugTracingCallOptions {
        state_overrides: Some(state_override),
        ..Default::default()
    };

    // With balance override and no explicit gas, it should succeed
    let result_with_override = evm.debug_trace_call(
        tx_req,
        Some(BlockNumberOrTag::Latest.into()),
        Some(opts),
        &mut working_set,
        &ledger_db,
    );

    assert!(
        result_with_override.is_ok(),
        "Balance override should make debug_traceCall succeed without explicit gas, but got error: {:?}",
        result_with_override.unwrap_err()
    );
}
