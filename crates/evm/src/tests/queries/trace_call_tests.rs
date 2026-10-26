use std::str::FromStr;

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::map::AddressMap;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_rpc_types::state::AccountOverride;
use alloy_rpc_types::TransactionRequest;
use alloy_rpc_types_trace::geth::{
    CallConfig, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingCallOptions,
    GethDebugTracingOptions, GethDefaultTracingOptions, TraceResult,
};
use sov_modules_api::WorkingSet;

use crate::tests::queries::{
    init_evm_log_block, init_evm_prefix_regression_block, init_evm_single_block,
};
use crate::tests::utils::get_fork_fn_latest;

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
        /* memory_limit_mb */ 512,
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
        /* memory_limit_mb */ 512,
    );

    assert!(
        result_with_override.is_ok(),
        "Balance override should make debug_traceCall succeed without explicit gas, but got error: {:?}",
        result_with_override.unwrap_err()
    );
}

/// Test that debug_traceCall disables base fee validation.
/// A transaction with gas_price below the base fee should still succeed
#[test]
fn test_debug_trace_call_disables_base_fee() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        )),
        value: Some(U256::from(1000)),
        gas_price: Some(1), // 1 wei, much lower than the block's base fee
        ..Default::default()
    };
    let result = evm.debug_trace_call(
        tx_req,
        Some(BlockNumberOrTag::Latest.into()),
        None,
        &mut working_set,
        &ledger_db,
        /* memory_limit_mb */ 512,
    );

    assert!(
        result.is_ok(),
        "debug_traceCall should succeed with gas_price below base fee, but got error: {:?}",
        result.unwrap_err()
    );

    // A second call with gas price omitted request
    let tx_req_no_gas_price = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        )),
        value: Some(U256::from(1000)),
        // gas_price is intentionally omitted to test default handling
        ..Default::default()
    };
    let result_no_gas_price = evm.debug_trace_call(
        tx_req_no_gas_price,
        Some(BlockNumberOrTag::Latest.into()),
        None,
        &mut working_set,
        &ledger_db,
        /* memory_limit_mb */ 512,
    );

    assert!(
        result_no_gas_price.is_ok(),
        "debug_traceCall should succeed with gas_price omitted, but got error: {:?}",
        result_no_gas_price.unwrap_err()
    );
}

/// A trace that would retain more than the configured memory limit is aborted with an error
/// instead of being allowed to allocate without bound.
#[test]
fn test_debug_trace_call_memory_limit() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let contract = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
    // JUMPDEST; PUSH1 0x00; JUMP - loops until it runs out of gas
    let mut state_override = AddressMap::default();
    state_override.insert(
        contract,
        AccountOverride {
            code: Some(Bytes::from_static(&[0x5b, 0x60, 0x00, 0x56])),
            ..Default::default()
        },
    );

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(contract)),
        gas: Some(500_000),
        ..Default::default()
    };
    let opts = GethDebugTracingCallOptions {
        state_overrides: Some(state_override),
        ..Default::default()
    };

    // the default structlog tracer retains a step per opcode, so a 1MB budget is exhausted long
    // before the loop runs out of gas
    let err = evm
        .debug_trace_call(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest.into()),
            Some(opts.clone()),
            &mut working_set,
            &ledger_db,
            /* memory_limit_mb */ 1,
        )
        .expect_err("trace of a gas burning loop should exceed a 1MB limit");
    assert!(
        format!("{err:?}").contains("memory limit"),
        "expected a memory limit error, got: {err:?}"
    );

    // the very same trace completes when the limit is disabled
    let result = evm.debug_trace_call(
        tx_req,
        Some(BlockNumberOrTag::Latest.into()),
        Some(opts),
        &mut working_set,
        &ledger_db,
        /* memory_limit_mb */ 0,
    );
    assert!(
        result.is_ok(),
        "trace should succeed without a limit, but got error: {:?}",
        result.unwrap_err()
    );
}

/// A root call returning more than the budget must be rejected. Its output is charged in
/// `call_end`, after the last `step` - and the call tracer records no per-step memory, so no step
/// ever sees the 2 MiB. Only the post-execution re-check catches it.
#[test]
fn test_debug_trace_call_memory_limit_root_return() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    // PUSH3 0x200000 (2 MiB); PUSH1 0x00; RETURN - returns 2 MiB of zeroed memory.
    let contract = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
    let mut state_override = AddressMap::default();
    state_override.insert(
        contract,
        AccountOverride {
            code: Some(Bytes::from_static(&[
                0x62, 0x20, 0x00, 0x00, 0x60, 0x00, 0xf3,
            ])),
            ..Default::default()
        },
    );

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(contract)),
        gas: Some(20_000_000),
        ..Default::default()
    };
    // Call tracer records no per-step memory, so the 2 MiB return is only charged in call_end.
    let opts = GethDebugTracingCallOptions {
        tracing_options: GethDebugTracingOptions::default().with_tracer(
            GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
        ),
        state_overrides: Some(state_override),
        ..Default::default()
    };

    let err = evm
        .debug_trace_call(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest.into()),
            Some(opts.clone()),
            &mut working_set,
            &ledger_db,
            /* memory_limit_mb */ 1,
        )
        .expect_err("a 2 MiB root return must exceed a 1 MiB limit");
    assert!(
        format!("{err:?}").contains("memory limit"),
        "expected a memory limit error, got: {err:?}"
    );

    // The same trace completes when the limit is disabled.
    let result = evm.debug_trace_call(
        tx_req,
        Some(BlockNumberOrTag::Latest.into()),
        Some(opts),
        &mut working_set,
        &ledger_db,
        /* memory_limit_mb */ 0,
    );
    assert!(
        result.is_ok(),
        "trace should succeed without a limit, but got error: {:?}",
        result.unwrap_err()
    );
}

/// A prestate response that would retain more than the budget is aborted as it is built, before
/// the whole response is allocated. A prestate tracer records no opcode steps, so without the
/// size check in the builder this 2 MiB of contract code would never be charged against the
/// budget.
#[test]
fn test_debug_trace_call_prestate_memory_limit() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    // 2 MiB of code, all STOP (0x00), so execution halts on the first byte. The prestate response
    // must carry this contract's full code, so the response alone exceeds a 1 MiB budget.
    let contract = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
    let mut state_override = AddressMap::default();
    state_override.insert(
        contract,
        AccountOverride {
            code: Some(Bytes::from(vec![0x00u8; 2 * 1024 * 1024])),
            ..Default::default()
        },
    );

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(contract)),
        gas: Some(1_000_000),
        ..Default::default()
    };
    let opts = GethDebugTracingCallOptions {
        tracing_options: GethDebugTracingOptions::default().with_tracer(
            GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::PreStateTracer),
        ),
        state_overrides: Some(state_override),
        ..Default::default()
    };

    let err = evm
        .debug_trace_call(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest.into()),
            Some(opts.clone()),
            &mut working_set,
            &ledger_db,
            /* memory_limit_mb */ 1,
        )
        .expect_err("a 2 MiB prestate response must exceed a 1 MiB limit");
    // The builder only saw what execution left of the budget; the error still names the full 1 MiB.
    assert!(
        format!("{err:?}").contains("memory limit of 1048576 bytes"),
        "expected the configured 1 MiB memory limit error, got: {err:?}"
    );

    // The same trace completes when the limit is disabled.
    let result = evm.debug_trace_call(
        tx_req,
        Some(BlockNumberOrTag::Latest.into()),
        Some(opts),
        &mut working_set,
        &ledger_db,
        /* memory_limit_mb */ 0,
    );
    assert!(
        result.is_ok(),
        "prestate trace should succeed without a limit, but got error: {:?}",
        result.unwrap_err()
    );
}

/// Retained log payloads count against the budget, but only when the tracer keeps them. A call
/// tracer with `withLog` retains a 2 MiB log and must blow a 1 MiB budget; without `withLog` the
/// same log isn't retained, so charging it would be a false abort - the trace must still succeed.
#[test]
fn test_debug_trace_call_memory_limit_logs() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    // PUSH3 0x200000 (2 MiB); PUSH1 0x00; LOG0; STOP - emits one 2 MiB, zero-topic log.
    let contract = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
    let mut state_override = AddressMap::default();
    state_override.insert(
        contract,
        AccountOverride {
            code: Some(Bytes::from_static(&[
                0x62, 0x20, 0x00, 0x00, 0x60, 0x00, 0xa0, 0x00,
            ])),
            ..Default::default()
        },
    );

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(contract)),
        gas: Some(40_000_000),
        ..Default::default()
    };
    let call_tracer = |with_log: bool| {
        let config = if with_log {
            CallConfig::default().with_log()
        } else {
            CallConfig::default()
        };
        GethDebugTracingCallOptions {
            tracing_options: GethDebugTracingOptions::call_tracer(config),
            state_overrides: Some(state_override.clone()),
            ..Default::default()
        }
    };

    // withLog: the 2 MiB log is retained, so it must exceed a 1 MiB budget.
    let err = evm
        .debug_trace_call(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest.into()),
            Some(call_tracer(true)),
            &mut working_set,
            &ledger_db,
            /* memory_limit_mb */ 1,
        )
        .expect_err("a 2 MiB log must exceed a 1 MiB limit with withLog");
    assert!(
        format!("{err:?}").contains("memory limit"),
        "expected a memory limit error, got: {err:?}"
    );

    // Without withLog the log isn't retained, so it must not be charged: the trace fits.
    let ok = evm.debug_trace_call(
        tx_req,
        Some(BlockNumberOrTag::Latest.into()),
        Some(call_tracer(false)),
        &mut working_set,
        &ledger_db,
        /* memory_limit_mb */ 1,
    );
    assert!(
        ok.is_ok(),
        "a trace that does not retain logs must not be charged for them, but got: {:?}",
        ok.unwrap_err()
    );
}

/// A MuxTracer holding `callTracer: {withLog: true}` retains the same logs the direct call tracer
/// does, so its budget must charge them too. A 2 MiB log must blow a 1 MiB budget through the mux;
/// without `withLog` the log isn't retained and the trace must still fit.
#[test]
fn test_debug_trace_call_mux_memory_limit_logs() {
    use std::collections::HashMap;

    use alloy_rpc_types_trace::geth::mux::MuxConfig;

    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    // PUSH3 0x200000 (2 MiB); PUSH1 0x00; LOG0; STOP - emits one 2 MiB, zero-topic log.
    let contract = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
    let mut state_override = AddressMap::default();
    state_override.insert(
        contract,
        AccountOverride {
            code: Some(Bytes::from_static(&[
                0x62, 0x20, 0x00, 0x00, 0x60, 0x00, 0xa0, 0x00,
            ])),
            ..Default::default()
        },
    );

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(contract)),
        gas: Some(40_000_000),
        ..Default::default()
    };
    let mux_tracer = |with_log: bool| {
        let call_config = CallConfig {
            with_log: Some(with_log),
            ..Default::default()
        };
        let mut tracing_options = GethDebugTracingOptions::default().with_tracer(
            GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::MuxTracer),
        );
        tracing_options.tracer_config = MuxConfig(HashMap::from_iter([(
            GethDebugBuiltInTracerType::CallTracer,
            Some(call_config.into()),
        )]))
        .into();
        GethDebugTracingCallOptions {
            tracing_options,
            state_overrides: Some(state_override.clone()),
            ..Default::default()
        }
    };

    // withLog: the 2 MiB log is retained through the mux, so it must exceed a 1 MiB budget.
    let err = evm
        .debug_trace_call(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest.into()),
            Some(mux_tracer(true)),
            &mut working_set,
            &ledger_db,
            /* memory_limit_mb */ 1,
        )
        .expect_err("a 2 MiB log must exceed a 1 MiB limit with mux withLog");
    assert!(
        format!("{err:?}").contains("memory limit"),
        "expected a memory limit error, got: {err:?}"
    );

    // Without withLog the log isn't retained, so it must not be charged: the trace fits.
    let ok = evm.debug_trace_call(
        tx_req,
        Some(BlockNumberOrTag::Latest.into()),
        Some(mux_tracer(false)),
        &mut working_set,
        &ledger_db,
        /* memory_limit_mb */ 1,
    );
    assert!(
        ok.is_ok(),
        "a mux trace that does not retain logs must not be charged for them, but got: {:?}",
        ok.unwrap_err()
    );
}

/// The memory snapshot a step retains has to be charged after a call returns.
///
/// The tracer reuses the previous step's snapshot only when the previous step of the *same* frame
/// left memory alone. Right after a call returns, that previous step is the call opcode, which is
/// in `OpCode::modifies_memory`, so the tracer allocates a fresh copy of the parent's whole memory
/// no matter what the callee did.
///
/// The gas limit here is picked so the trace only trips the budget if those snapshots are charged:
/// ~190 iterations retain ~12MB of snapshots but only ~1MB of step records, against a 4MB budget.
#[test]
fn test_debug_trace_call_memory_limit_charges_snapshot_after_call() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let contract = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
    let callee = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();

    let mut caller_code = vec![
        // grow memory to 64KB once, so every later snapshot is expensive
        0x5f, 0x62, 0x01, 0x00, 0x00, 0x52, // PUSH0; PUSH3 0x010000; MSTORE
        // loop: call the callee with no arguments, so the only thing an iteration retains is the
        // snapshot the parent takes on its first step after the call returns
        0x5b, // JUMPDEST (pc 6)
        0x5f, 0x5f, 0x5f, 0x5f, 0x5f, // 5x PUSH0 (retLength..value)
        0x73, // PUSH20 callee
    ];
    caller_code.extend_from_slice(callee.as_slice());
    caller_code.extend_from_slice(&[
        0x5f, 0xf1, 0x50, // PUSH0 (gas); CALL; POP
        0x60, 0x06, 0x56, // PUSH1 6; JUMP
    ]);

    let mut state_override = AddressMap::default();
    state_override.insert(
        contract,
        AccountOverride {
            code: Some(caller_code.into()),
            ..Default::default()
        },
    );
    state_override.insert(
        callee,
        AccountOverride {
            // a single STOP: the callee runs one step that leaves memory alone, which is what
            // makes a tracked-per-execution flag lose the fact that the parent's next step
            // reallocates
            code: Some(Bytes::from_static(&[0x00])),
            ..Default::default()
        },
    );

    let err = evm
        .debug_trace_call(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(contract)),
                gas: Some(60_000),
                ..Default::default()
            },
            Some(BlockNumberOrTag::Latest.into()),
            Some(GethDebugTracingCallOptions {
                state_overrides: Some(state_override),
                tracing_options: GethDebugTracingOptions {
                    config: GethDefaultTracingOptions {
                        enable_memory: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            }),
            &mut working_set,
            &ledger_db,
            /* memory_limit_mb */ 4,
        )
        .expect_err("memory snapshots retained after each call should exhaust the limit");
    assert!(
        format!("{err:?}").contains("memory limit"),
        "expected a memory limit error, got: {err:?}"
    );
}

/// Call frames must come back in the order they were made, at every level of nesting.
///
/// The trace arena is walked from the deepest frame up, so the builder sees a parent's children in
/// reverse; how it puts them back in order is easy to get subtly wrong.
#[test]
fn test_debug_trace_call_orders_sibling_and_nested_calls() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let addr = |byte: u8| Address::from([byte; 20]);
    let (caller, a, b, c, d, e) = (
        addr(1),
        addr(0xa),
        addr(0xb),
        addr(0xc),
        addr(0xd),
        addr(0xe),
    );

    // PUSH0 x5 (retLength..value); PUSH20 target; GAS; CALL; POP - once per target
    let call_sequence = |targets: &[Address]| {
        let mut code = Vec::new();
        for target in targets {
            code.extend_from_slice(&[0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x73]);
            code.extend_from_slice(target.as_slice());
            code.extend_from_slice(&[0x5a, 0xf1, 0x50]);
        }
        Bytes::from(code)
    };

    let mut state_override = AddressMap::default();
    state_override.insert(
        caller,
        AccountOverride {
            code: Some(call_sequence(&[a, b, c])),
            ..Default::default()
        },
    );
    // the middle sibling makes calls of its own, so ordering has to hold one level down too
    state_override.insert(
        b,
        AccountOverride {
            code: Some(call_sequence(&[d, e])),
            ..Default::default()
        },
    );
    for leaf in [a, c, d, e] {
        state_override.insert(
            leaf,
            AccountOverride {
                code: Some(Bytes::from_static(&[0x00])), // STOP
                ..Default::default()
            },
        );
    }

    let trace = evm
        .debug_trace_call(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(caller)),
                gas: Some(1_000_000),
                ..Default::default()
            },
            Some(BlockNumberOrTag::Latest.into()),
            Some(GethDebugTracingCallOptions {
                state_overrides: Some(state_override),
                tracing_options: GethDebugTracingOptions {
                    tracer: Some(GethDebugTracerType::BuiltInTracer(
                        GethDebugBuiltInTracerType::CallTracer,
                    )),
                    ..Default::default()
                },
                ..Default::default()
            }),
            &mut working_set,
            &ledger_db,
            /* memory_limit_mb */ 512,
        )
        .expect("trace should succeed");

    let root = trace.try_into_call_frame().expect("call tracer frame");
    assert_eq!(
        root.calls.iter().map(|call| call.to).collect::<Vec<_>>(),
        vec![Some(a), Some(b), Some(c)],
        "top level calls out of order"
    );
    assert_eq!(
        root.calls[1]
            .calls
            .iter()
            .map(|call| call.to)
            .collect::<Vec<_>>(),
        vec![Some(d), Some(e)],
        "nested calls out of order"
    );
}

/// A selfdestruct is reported as a synthetic frame *after* the real calls of the frame it belongs
/// to. It is not a recorded call, it is derived from the node, so it is easy to move by accident
/// when changing how children are ordered.
#[test]
fn test_debug_trace_call_places_selfdestruct_after_calls() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let addr = |byte: u8| Address::from([byte; 20]);
    let (caller, callee, beneficiary) = (addr(1), addr(0xa), addr(0xb));

    // PUSH0 x5; PUSH20 callee; GAS; CALL; POP; PUSH20 beneficiary; SELFDESTRUCT
    let mut code = vec![0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x73];
    code.extend_from_slice(callee.as_slice());
    code.extend_from_slice(&[0x5a, 0xf1, 0x50, 0x73]);
    code.extend_from_slice(beneficiary.as_slice());
    code.push(0xff);

    let mut state_override = AddressMap::default();
    state_override.insert(
        caller,
        AccountOverride {
            code: Some(code.into()),
            ..Default::default()
        },
    );
    state_override.insert(
        callee,
        AccountOverride {
            code: Some(Bytes::from_static(&[0x00])), // STOP
            ..Default::default()
        },
    );

    let trace = evm
        .debug_trace_call(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(caller)),
                gas: Some(1_000_000),
                ..Default::default()
            },
            Some(BlockNumberOrTag::Latest.into()),
            Some(GethDebugTracingCallOptions {
                state_overrides: Some(state_override),
                tracing_options: GethDebugTracingOptions {
                    tracer: Some(GethDebugTracerType::BuiltInTracer(
                        GethDebugBuiltInTracerType::CallTracer,
                    )),
                    ..Default::default()
                },
                ..Default::default()
            }),
            &mut working_set,
            &ledger_db,
            /* memory_limit_mb */ 512,
        )
        .expect("trace should succeed");

    let root = trace.try_into_call_frame().expect("call tracer frame");
    assert_eq!(
        root.calls
            .iter()
            .map(|call| call.typ.as_str())
            .collect::<Vec<_>>(),
        vec!["CALL", "SELFDESTRUCT"],
        "the selfdestruct frame must come after the calls of its frame"
    );
}

/// Storage writes have to be charged for what they cost in the *output*, not in the arena.
///
/// The struct log builder gives every step that changed storage a copy of all storage of that
/// contract seen so far, so N writes across K slots build N copies of a growing map while the
/// arena only grows by one `CallTraceStep` per step. Storage recording is on by default, so this
/// needs no tracer options at all.
#[test]
fn test_debug_trace_call_memory_limit_charges_storage_copies() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let contract = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
    let mut state_override = AddressMap::default();
    state_override.insert(
        contract,
        AccountOverride {
            // loop: write to a new slot every iteration, so the map the builder copies grows by
            // one each time while the arena only grows by 8 steps
            code: Some(Bytes::from_static(&[
                0x5f, // PUSH0            (slot counter)
                0x5b, // JUMPDEST (pc 1)
                0x60, 0x01, // PUSH1 1
                0x01, // ADD              (counter += 1)
                0x80, 0x80, // DUP1; DUP1  (key and value both = counter)
                0x55, // SSTORE
                0x60, 0x01, 0x56, // PUSH1 1; JUMP -> back to pc 1
            ])),
            ..Default::default()
        },
    );

    let err = evm
        .debug_trace_call(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(contract)),
                gas: Some(25_000_000),
                ..Default::default()
            },
            Some(BlockNumberOrTag::Latest.into()),
            Some(GethDebugTracingCallOptions {
                state_overrides: Some(state_override),
                ..Default::default()
            }),
            &mut working_set,
            &ledger_db,
            // ~1100 slots fit in the gas: ~3.7MB of step records, but ~40MB of storage copies
            /* memory_limit_mb */
            8,
        )
        .expect_err("repeated storage writes should exhaust the limit through their output copies");
    assert!(
        format!("{err:?}").contains("memory limit"),
        "expected a memory limit error, got: {err:?}"
    );
}

/// Exceeding the limit inside a nested call frame unwinds through the parent frame, which is the
/// path revm asserts on if the abort is not accompanied by a context error.
#[test]
fn test_debug_trace_call_memory_limit_in_nested_call() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let caller = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
    let callee = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();

    // PUSH1 0x00 x5 (retLength, retOffset, argsLength, argsOffset, value); PUSH20 callee; GAS; CALL
    let mut caller_code = vec![
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73,
    ];
    caller_code.extend_from_slice(callee.as_slice());
    caller_code.extend_from_slice(&[0x5a, 0xf1]);

    let mut state_override = AddressMap::default();
    state_override.insert(
        caller,
        AccountOverride {
            code: Some(caller_code.into()),
            ..Default::default()
        },
    );
    state_override.insert(
        callee,
        AccountOverride {
            // JUMPDEST; PUSH1 0x00; JUMP - loops until it runs out of gas
            code: Some(Bytes::from_static(&[0x5b, 0x60, 0x00, 0x56])),
            ..Default::default()
        },
    );

    let err = evm
        .debug_trace_call(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(caller)),
                gas: Some(500_000),
                ..Default::default()
            },
            Some(BlockNumberOrTag::Latest.into()),
            Some(GethDebugTracingCallOptions {
                state_overrides: Some(state_override),
                ..Default::default()
            }),
            &mut working_set,
            &ledger_db,
            /* memory_limit_mb */ 1,
        )
        .expect_err("trace of a gas burning loop should exceed a 1MB limit");
    assert!(
        format!("{err:?}").contains("memory limit"),
        "expected a memory limit error, got: {err:?}"
    );
}

/// Test that debug_traceCall disables EIP-3607 validation.
/// EIP-3607 rejects transactions from senders that have deployed contract code.
#[test]
fn test_debug_trace_call_disables_eip3607() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    // Use a state override to give the sender account some contract code
    // This would normally trigger EIP-3607 rejection
    let mut state_override = AddressMap::default();
    state_override.insert(
        signer.address(),
        AccountOverride {
            // Add some dummy contract code to the sender's account
            code: Some(Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xf3])), // PUSH 0, PUSH 0, RETURN
            ..Default::default()
        },
    );

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        )),
        value: Some(U256::from(1000)),
        ..Default::default()
    };

    let opts = GethDebugTracingCallOptions {
        state_overrides: Some(state_override),
        ..Default::default()
    };

    let result = evm.debug_trace_call(
        tx_req,
        Some(BlockNumberOrTag::Latest.into()),
        Some(opts),
        &mut working_set,
        &ledger_db,
        /* memory_limit_mb */ 512,
    );

    assert!(
        result.is_ok(),
        "debug_traceCall should succeed when sender has contract code, but got error: {:?}",
        result.unwrap_err()
    );
}

/// Regression test: tracing one transaction must not trace the transactions before it.
///
/// A single memory budget covers a whole `debug_trace*` request. When the request asks for one
/// transaction, the transactions before it only need to run so their state carries forward, and
/// tracing them would spend the target's budget on traces that are thrown away. A shared budget
/// that charged the prefix made a late transaction in a busy block permanently untraceable.
///
/// The block here has two gas-burning transactions before a cheap value transfer. Against a budget
/// that is far too small to trace a gas-burning loop, tracing the transfer must still succeed,
/// because the two loops before it are executed and not traced.
#[test]
fn test_debug_trace_transaction_does_not_trace_prefix() {
    let (evm, storage, block_number, ledger_db) =
        init_evm_prefix_regression_block(sov_modules_api::SpecId::latest());
    let fork_fn = get_fork_fn_latest();

    // Enough for the transfer's near-empty trace, far too small for a gas-burning loop's tens of
    // megabytes of struct-log steps.
    let limit_mb = 8;

    // Sanity: a gas-burning transaction is over budget on its own, so the limit really does bite.
    let mut working_set = WorkingSet::new(storage.clone());
    let over_budget = evm.trace_block_transactions_by_number(
        block_number,
        None,
        Some(1),
        &mut working_set,
        &ledger_db,
        &fork_fn,
        limit_mb,
    );
    let err = over_budget.expect_err("a gas-burning trace should exceed the 8MB budget");
    assert!(
        format!("{err:?}").contains("memory limit"),
        "expected a memory limit error, got: {err:?}"
    );

    // The cheap transfer at index 3 traces within budget: the two gas-burning transactions before
    // it are executed to advance state, not traced, so they cost nothing against the budget.
    let mut working_set = WorkingSet::new(storage.clone());
    let traces = evm
        .trace_block_transactions_by_number(
            block_number,
            None,
            Some(3),
            &mut working_set,
            &ledger_db,
            &fork_fn,
            limit_mb,
        )
        .expect("tracing a late cheap tx must not be charged for the traced prefix");

    assert_eq!(
        traces.len(),
        1,
        "only the requested transaction should be returned, not the executed prefix"
    );
    assert!(
        matches!(traces[0], TraceResult::Success { .. }),
        "the requested transaction should trace successfully, got: {:?}",
        traces[0]
    );
}

/// Same budget, two requests: tracing the whole block busts it, tracing one late transaction does
/// not. This is the direct payoff of executing the prefix instead of tracing it. Before the fix,
/// the single-transaction request traced the heavy prefix too and busted the very same budget.
#[test]
fn test_debug_trace_transaction_fits_budget_that_whole_block_busts() {
    let (evm, storage, block_number, ledger_db) =
        init_evm_prefix_regression_block(sov_modules_api::SpecId::latest());
    let fork_fn = get_fork_fn_latest();

    // Too small to trace the whole block (two gas-burning loops), large enough for one cheap tx.
    let limit_mb = 8;

    // Whole block: every transaction is traced, so the two gas-burning loops bust the budget.
    let mut working_set = WorkingSet::new(storage.clone());
    let whole_block = evm.trace_block_transactions_by_number(
        block_number,
        None,
        None,
        &mut working_set,
        &ledger_db,
        &fork_fn,
        limit_mb,
    );
    let err = whole_block.expect_err("tracing the whole block should exceed the 8MB budget");
    assert!(
        format!("{err:?}").contains("memory limit"),
        "expected a memory limit error tracing the whole block, got: {err:?}"
    );

    // The late transaction alone, under the same budget: the heavy prefix is executed, not traced,
    // so the budget is spent only on the target and the request succeeds.
    let mut working_set = WorkingSet::new(storage.clone());
    let single = evm
        .trace_block_transactions_by_number(
            block_number,
            None,
            Some(3),
            &mut working_set,
            &ledger_db,
            &fork_fn,
            limit_mb,
        )
        .expect("the late tx alone must fit the budget the whole block busts");
    assert_eq!(
        single.len(),
        1,
        "only the requested transaction is returned"
    );
    assert!(
        matches!(single[0], TraceResult::Success { .. }),
        "the requested transaction should trace successfully, got: {:?}",
        single[0]
    );
}

/// The same `withLog` accounting the `debug_traceCall` mux path makes must also hold on the
/// `debug_traceTransaction` / `debug_traceBlock*` path, which builds its budget at a separate call
/// site. A mux `{callTracer: {withLog: true}}` over a transaction emitting a 2 MiB log must blow a
/// 1 MiB budget; without `withLog` the log isn't retained and the trace must still fit.
#[test]
fn test_debug_trace_transaction_mux_memory_limit_logs() {
    use std::collections::HashMap;

    use alloy_rpc_types_trace::geth::mux::MuxConfig;

    let (evm, storage, block_number, ledger_db) =
        init_evm_log_block(sov_modules_api::SpecId::latest());
    let fork_fn = get_fork_fn_latest();

    let mux_opts = |with_log: bool| {
        let call_config = CallConfig {
            with_log: Some(with_log),
            ..Default::default()
        };
        let mut opts = GethDebugTracingOptions::default().with_tracer(
            GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::MuxTracer),
        );
        opts.tracer_config = MuxConfig(HashMap::from_iter([(
            GethDebugBuiltInTracerType::CallTracer,
            Some(call_config.into()),
        )]))
        .into();
        opts
    };

    // withLog: the 2 MiB log is retained through the mux, so it must exceed a 1 MiB budget. The
    // transaction at index 0 (the deploy) is executed as prefix, not traced.
    let mut working_set = WorkingSet::new(storage.clone());
    let err = evm
        .trace_block_transactions_by_number(
            block_number,
            Some(mux_opts(true)),
            Some(1),
            &mut working_set,
            &ledger_db,
            &fork_fn,
            /* memory_limit_mb */ 1,
        )
        .expect_err("a 2 MiB log must exceed a 1 MiB limit with mux withLog");
    assert!(
        format!("{err:?}").contains("memory limit"),
        "expected a memory limit error, got: {err:?}"
    );

    // Without withLog the log isn't retained, so it must not be charged: the trace fits.
    let mut working_set = WorkingSet::new(storage.clone());
    let ok = evm.trace_block_transactions_by_number(
        block_number,
        Some(mux_opts(false)),
        Some(1),
        &mut working_set,
        &ledger_db,
        &fork_fn,
        /* memory_limit_mb */ 1,
    );
    assert!(
        ok.is_ok(),
        "a mux trace that does not retain logs must not be charged for them, but got: {:?}",
        ok.unwrap_err()
    );
}
