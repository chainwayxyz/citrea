use alloy_primitives::{TxHash, U256};
use alloy_rpc_types::TransactionInfo;
use alloy_rpc_types_trace::geth::call::FlatCallFrame;
use alloy_rpc_types_trace::geth::{
    FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
    GethTrace, NoopFrame,
};
use reth_rpc_eth_api::FromEthApiError;
use reth_rpc_eth_types::error::{EthApiError, EthResult, RpcInvalidTransactionError};
use revm::context::result::{EVMError, ResultAndState};
use revm::context::{Cfg, CfgEnv, JournalTr, Transaction, TxEnv};
use revm::{Context, ExecuteEvm, InspectEvm, Inspector, Journal};
use revm_inspectors::tracing::geth::PrestateError;
use revm_inspectors::tracing::js::JsInspector;
use revm_inspectors::tracing::{
    FourByteInspector, MuxInspector, TracingInspector, TracingInspectorConfig, TransactionContext,
};

use crate::db::{AccountExistsProvider, DBError};
use crate::evm::db::immutable::EvmDbRef;
use crate::evm::db::EvmDb;
use crate::handler::{CitreaBuilder, CitreaChain, CitreaChainExt, CitreaContext, TxInfo};
use crate::rpc_helpers::trace_limit::{
    trace_memory_limit_exceeded, TraceMemoryBudget, TraceMemoryLimiter, TraceMemoryUsage,
};
use crate::rpc_helpers::*;

/// Maps a prestate build error to an RPC error: a response that would exceed the trace memory
/// budget becomes the same memory-limit error the step budget raises mid-execution, everything
/// else is the underlying database error.
fn map_prestate_err<E>(err: PrestateError<E>, usage: &TraceMemoryUsage) -> EthApiError
where
    EthApiError: From<E>,
{
    match err {
        PrestateError::Database(e) => EthApiError::from_eth_err(e),
        PrestateError::MaxResponseSize { .. } => EthApiError::EvmCustom(usage.response_too_large()),
    }
}

pub(crate) fn trace_call<C: sov_modules_api::Context>(
    tracing_options: GethDebugTracingOptions,
    config_env: CfgEnv,
    block_env: BlockEnv,
    tx_env: TxEnv,
    db: &mut EvmDb<'_, C>,
    l1_fee_rate: u128,
    usage: &TraceMemoryUsage,
) -> EthResult<GethTrace> {
    let GethDebugTracingOptions {
        config,
        tracer,
        tracer_config,
        ..
    } = tracing_options;

    if let Some(tracer) = tracer {
        return match tracer {
            GethDebugTracerType::BuiltInTracer(tracer) => match tracer {
                GethDebugBuiltInTracerType::FourByteTracer => {
                    let mut inspector = FourByteInspector::default();
                    let _ = trace_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        None,
                        l1_fee_rate,
                        &mut inspector,
                        TraceMemoryBudget::opaque(usage),
                    )?;
                    return Ok(FourByteFrame::from(inspector).into());
                }
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config
                        .into_call_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;

                    let inspector_config =
                        TracingInspectorConfig::from_geth_call_config(&call_config);
                    let mut inspector = TracingInspector::new(inspector_config);

                    let mut db_ref = EvmDbRef::new(db);
                    let res = trace_citrea(
                        &mut db_ref,
                        config_env.clone(),
                        block_env.clone(),
                        tx_env.clone(),
                        None,
                        l1_fee_rate,
                        &mut inspector,
                        TraceMemoryBudget::steps(usage, &inspector_config),
                    )?;
                    let frame = inspector
                        .into_geth_builder()
                        .geth_call_traces(call_config, res.result.gas_used());
                    Ok(frame.into())
                }
                GethDebugBuiltInTracerType::PreStateTracer => {
                    let prestate_config = tracer_config
                        .into_pre_state_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;
                    let inspector_config =
                        TracingInspectorConfig::from_geth_prestate_config(&prestate_config);
                    let mut inspector = TracingInspector::new(inspector_config);

                    let mut db_ref = EvmDbRef::new(db);
                    let res = trace_citrea(
                        &mut db_ref,
                        config_env,
                        block_env,
                        tx_env.clone(),
                        None,
                        l1_fee_rate,
                        &mut inspector,
                        TraceMemoryBudget::steps(usage, &inspector_config),
                    )?;
                    let (frame, size) = inspector
                        .with_transaction_gas_limit(tx_env.gas_limit())
                        .into_geth_builder()
                        .geth_prestate_traces_with_size_limit(
                            &res,
                            &prestate_config,
                            &db_ref,
                            usage.remaining(),
                        )
                        .map_err(|e| map_prestate_err(e, usage))?;
                    // Charge the retained prestate against the shared request budget: it is built
                    // after execution, so no per-step charge covered it, and a block traces many
                    // transactions against this same budget.
                    usage.charge(size);

                    Ok(frame.into())
                }
                GethDebugBuiltInTracerType::FlatCallTracer => {
                    let flat_call_config = tracer_config
                        .into_flat_call_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;

                    let inspector_config =
                        TracingInspectorConfig::from_flat_call_config(&flat_call_config);
                    let mut inspector = TracingInspector::new(inspector_config);

                    let mut db_ref = EvmDbRef::new(db);
                    let _res = trace_citrea(
                        &mut db_ref,
                        config_env,
                        block_env,
                        tx_env.clone(),
                        None,
                        l1_fee_rate,
                        &mut inspector,
                        TraceMemoryBudget::steps(usage, &inspector_config),
                    )?;
                    let tx_info = TransactionInfo::default();
                    let (frame, size): (FlatCallFrame, usize) = inspector
                        .with_transaction_gas_limit(tx_env.gas_limit())
                        .into_parity_builder()
                        .try_into_localized_transaction_traces_with_size_limit(
                            tx_info,
                            usage.remaining(),
                        )
                        .map_err(|_| EthApiError::EvmCustom(usage.response_too_large()))?;
                    // The traceAddress vectors are built after execution, so no per-step charge
                    // covered them; charge them against the shared request budget.
                    usage.charge(size);
                    Ok(frame.into())
                }
                GethDebugBuiltInTracerType::MuxTracer => {
                    let mux_config = tracer_config
                        .into_mux_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;

                    let mut inspector = MuxInspector::try_from_config(mux_config)
                        .map_err(EthApiError::from_eth_err)?;

                    // Charge the budget the mux's inner tracing inspector actually retains: a mux
                    // holding `callTracer: {withLog: true}` keeps every log, which `call_frames`
                    // would never charge. `tracing_config` is the merged config of all muxed
                    // tracers; `None` means only the four byte / noop tracers are present, which
                    // retain nothing attributable to a frame - so use the same opaque budget as a
                    // standalone four byte tracer rather than `call_frames`, which would charge the
                    // calldata of every frame and falsely reject a call-heavy transaction.
                    let budget = match inspector.tracing_config() {
                        Some(config) => TraceMemoryBudget::steps(usage, config),
                        None => TraceMemoryBudget::opaque(usage),
                    };

                    let mut db_ref = EvmDbRef::new(db);
                    let res = trace_citrea(
                        &mut db_ref,
                        config_env,
                        block_env.clone(),
                        tx_env.clone(),
                        None,
                        l1_fee_rate,
                        &mut inspector,
                        budget,
                    )?;
                    let tx_info = TransactionInfo {
                        block_number: Some(block_env.number),
                        base_fee: Some(block_env.basefee),
                        hash: None,
                        block_hash: None,
                        index: None,
                    };

                    let (frame, size) = inspector
                        .try_into_mux_frame_with_size_limit(
                            &res,
                            &db_ref,
                            tx_info,
                            usage.remaining(),
                        )
                        .map_err(|e| map_prestate_err(e, usage))?;
                    // Charge the prestate and flat-call payload the mux retained against the shared
                    // request budget (see the direct prestate and flat-call paths).
                    usage.charge(size);
                    Ok(frame.into())
                }
                GethDebugBuiltInTracerType::NoopTracer => Ok(NoopFrame::default().into()),
            },
            GethDebugTracerType::JsTracer(code) => {
                let config = tracer_config.into_json();
                let mut inspector = JsInspector::new(code, config)
                    .map_err(|e| EthApiError::InternalJsTracerError(e.to_string()))?;

                let mut db_ref = EvmDbRef::new(db);
                let result_and_state = trace_citrea(
                    &mut db_ref,
                    config_env,
                    block_env.clone(),
                    tx_env.clone(),
                    None,
                    l1_fee_rate,
                    &mut inspector,
                    TraceMemoryBudget::opaque(usage),
                )?;

                let json_value = inspector
                    .json_result(result_and_state, &tx_env, &block_env, &db_ref)
                    .map_err(|e| EthApiError::InternalJsTracerError(e.to_string()))?;
                Ok(GethTrace::JS(json_value))
            }
        };
    }

    // default structlog tracer
    let inspector_config = TracingInspectorConfig::from_geth_config(&config);
    let mut inspector = TracingInspector::new(inspector_config);

    let res = trace_citrea(
        db,
        config_env,
        block_env,
        tx_env,
        None,
        l1_fee_rate,
        &mut inspector,
        TraceMemoryBudget::steps(usage, &inspector_config),
    )?;
    let gas_used = res.result.gas_used();
    let return_value = res.result.into_output().unwrap_or_default();
    let frame = inspector
        .into_geth_builder()
        .geth_traces(gas_used, return_value, config);

    Ok(frame.into())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn trace_transaction<C: sov_modules_api::Context>(
    opts: GethDebugTracingOptions,
    config_env: CfgEnv,
    block_env: BlockEnv,
    tx_env: TxEnv,
    tx_hash: &TxHash,
    db: &mut EvmDb<'_, C>,
    l1_fee_rate: u128,
    usage: &TraceMemoryUsage,
) -> EthResult<(GethTrace, revm::state::EvmState)> {
    let GethDebugTracingOptions {
        config,
        tracer,
        tracer_config,
        ..
    } = opts;

    if let Some(tracer) = tracer {
        return match tracer {
            GethDebugTracerType::BuiltInTracer(tracer) => match tracer {
                GethDebugBuiltInTracerType::FourByteTracer => {
                    let mut inspector = FourByteInspector::default();
                    let res = trace_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        Some(tx_hash),
                        l1_fee_rate,
                        &mut inspector,
                        TraceMemoryBudget::opaque(usage),
                    )?;
                    return Ok((FourByteFrame::from(inspector).into(), res.state));
                }
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config
                        .into_call_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;
                    // the call tracer only reads call frames, recording opcode level steps here
                    // would retain one `CallTraceStep` per executed opcode for nothing
                    let inspector_config =
                        TracingInspectorConfig::from_geth_call_config(&call_config);
                    let mut inspector = TracingInspector::new(inspector_config);
                    let res = trace_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        Some(tx_hash),
                        l1_fee_rate,
                        &mut inspector,
                        TraceMemoryBudget::steps(usage, &inspector_config),
                    )?;
                    let frame = inspector
                        .into_geth_builder()
                        .geth_call_traces(call_config, res.result.gas_used());
                    Ok((frame.into(), res.state))
                }
                GethDebugBuiltInTracerType::PreStateTracer => {
                    let prestate_config = tracer_config
                        .into_pre_state_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;
                    let inspector_config =
                        TracingInspectorConfig::from_geth_prestate_config(&prestate_config);
                    let mut inspector = TracingInspector::new(inspector_config);
                    let mut db_ref = EvmDbRef::new(db);
                    let res = trace_citrea(
                        &mut db_ref,
                        config_env,
                        block_env,
                        tx_env.clone(),
                        Some(tx_hash),
                        l1_fee_rate,
                        &mut inspector,
                        TraceMemoryBudget::steps(usage, &inspector_config),
                    )?;
                    let (frame, size) = inspector
                        .with_transaction_gas_limit(tx_env.gas_limit())
                        .into_geth_builder()
                        .geth_prestate_traces_with_size_limit(
                            &res,
                            &prestate_config,
                            db_ref,
                            usage.remaining(),
                        )
                        .map_err(|e| map_prestate_err(e, usage))?;
                    // Charge the retained prestate against the shared request budget: it is built
                    // after execution, so no per-step charge covered it, and a block traces many
                    // transactions against this same budget.
                    usage.charge(size);

                    Ok((frame.into(), res.state))
                }
                GethDebugBuiltInTracerType::FlatCallTracer => {
                    let flat_call_config = tracer_config
                        .into_flat_call_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;

                    let inspector_config =
                        TracingInspectorConfig::from_flat_call_config(&flat_call_config);
                    let mut inspector = TracingInspector::new(inspector_config);
                    let mut db_ref = EvmDbRef::new(db);
                    let res = trace_citrea(
                        &mut db_ref,
                        config_env,
                        block_env,
                        tx_env.clone(),
                        Some(tx_hash),
                        l1_fee_rate,
                        &mut inspector,
                        TraceMemoryBudget::steps(usage, &inspector_config),
                    )?;

                    let tx_info = TransactionInfo::default();
                    let (frame, size): (FlatCallFrame, usize) = inspector
                        .with_transaction_gas_limit(tx_env.gas_limit())
                        .into_parity_builder()
                        .try_into_localized_transaction_traces_with_size_limit(
                            tx_info,
                            usage.remaining(),
                        )
                        .map_err(|_| EthApiError::EvmCustom(usage.response_too_large()))?;
                    // The traceAddress vectors are built after execution, so no per-step charge
                    // covered them; charge them against the shared request budget.
                    usage.charge(size);
                    Ok((frame.into(), res.state))
                }
                GethDebugBuiltInTracerType::MuxTracer => {
                    let mux_config = tracer_config
                        .clone()
                        .into_mux_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;

                    let mut inspector = MuxInspector::try_from_config(mux_config)
                        .map_err(EthApiError::from_eth_err)?;

                    // Charge the budget the mux's inner tracing inspector actually retains: a mux
                    // holding `callTracer: {withLog: true}` keeps every log, which `call_frames`
                    // would never charge. `tracing_config` is the merged config of all muxed
                    // tracers; `None` means only the four byte / noop tracers are present, which
                    // retain nothing attributable to a frame - so use the same opaque budget as a
                    // standalone four byte tracer rather than `call_frames`, which would charge the
                    // calldata of every frame and falsely reject a call-heavy transaction.
                    let budget = match inspector.tracing_config() {
                        Some(config) => TraceMemoryBudget::steps(usage, config),
                        None => TraceMemoryBudget::opaque(usage),
                    };

                    let mut db_ref = EvmDbRef::new(db);
                    let res = trace_citrea(
                        &mut db_ref,
                        config_env,
                        block_env.clone(),
                        tx_env.clone(),
                        Some(tx_hash),
                        l1_fee_rate,
                        &mut inspector,
                        budget,
                    )?;
                    let tx_info = TransactionInfo {
                        block_number: Some(block_env.number),
                        base_fee: Some(block_env.basefee),
                        hash: None,
                        block_hash: None,
                        index: None,
                    };
                    let (frame, size) = inspector
                        .try_into_mux_frame_with_size_limit(
                            &res,
                            &db_ref,
                            tx_info,
                            usage.remaining(),
                        )
                        .map_err(|e| map_prestate_err(e, usage))?;
                    // Charge the prestate and flat-call payload the mux retained against the shared
                    // request budget (see the direct prestate and flat-call paths).
                    usage.charge(size);
                    return Ok((frame.into(), res.state));
                }
                GethDebugBuiltInTracerType::NoopTracer => {
                    Ok((NoopFrame::default().into(), Default::default()))
                }
            },
            GethDebugTracerType::JsTracer(code) => {
                let config = tracer_config.into_json();
                let transaction_context = TransactionContext {
                    block_hash: None,
                    tx_hash: Some(*tx_hash),
                    tx_index: None,
                };
                let mut inspector =
                    JsInspector::with_transaction_context(code, config, transaction_context)
                        .map_err(|e| EthApiError::InternalJsTracerError(e.to_string()))?;

                let mut db_ref = EvmDbRef::new(db);
                let result_and_state = trace_citrea(
                    &mut db_ref,
                    config_env.clone(),
                    block_env.clone(),
                    tx_env.clone(),
                    Some(tx_hash),
                    l1_fee_rate,
                    &mut inspector,
                    TraceMemoryBudget::opaque(usage),
                )?;
                let state = result_and_state.state.clone();

                let json_value = inspector
                    .json_result(result_and_state, &tx_env, &block_env, &db_ref)
                    .map_err(|e| EthApiError::InternalJsTracerError(e.to_string()))?;
                Ok((GethTrace::JS(json_value), state))
            }
        };
    }

    // default structlog tracer
    let inspector_config = TracingInspectorConfig::from_geth_config(&config);
    let mut inspector = TracingInspector::new(inspector_config);

    let res = trace_citrea(
        db,
        config_env,
        block_env,
        tx_env,
        Some(tx_hash),
        l1_fee_rate,
        &mut inspector,
        TraceMemoryBudget::steps(usage, &inspector_config),
    )?;
    let gas_used = res.result.gas_used();
    let return_value = res.result.into_output().unwrap_or_default();
    let frame = inspector
        .into_geth_builder()
        .geth_traces(gas_used, return_value, config);

    Ok((frame.into(), res.state))
}

/// Executes the [Env] against the given [Database] without committing state changes.
///
/// The trace is aborted with [`EVMError::Custom`] if the inspector retains more than `budget`
/// allows, see [`TraceMemoryLimiter`].
#[allow(clippy::too_many_arguments)]
fn trace_citrea<DB, I>(
    db: DB,
    config_env: CfgEnv,
    block_env: BlockEnv,
    tx_env: TxEnv,
    tx_hash: Option<&TxHash>,
    l1_fee_rate: u128,
    inspector: I,
    budget: TraceMemoryBudget<'_>,
) -> Result<ResultAndState, EVMError<<DB as revm::Database>::Error>>
where
    DB: Database + AccountExistsProvider,
    I: for<'c> Inspector<CitreaContext<'c, DB>>,
{
    let inspector = TraceMemoryLimiter::new(inspector, budget);
    let mut ext = CitreaChain::new(l1_fee_rate);

    let tx_hash = tx_hash.unwrap_or_else(|| b"hash_of_an_ephemeral_transaction".into());

    ext.set_current_tx_hash(tx_hash);

    let mut journal = Journal::new(db);
    journal.set_spec_id(config_env.spec());
    let mut evm = Context {
        block: block_env,
        cfg: config_env,
        chain: &mut ext,
        tx: tx_env,
        error: Ok(()),
        journaled_state: journal,
    }
    .build_citrea_with_inspector(inspector);

    let result = evm.inspect_replay()?;
    // `step` is the only hook that can abort, so a charge recorded after the last step - the root
    // frame's retained output, charged in `call_end` with no parent step to follow it - escapes the
    // in-flight check. Re-check the budget here, before the trace is handed back and retained.
    if let Some(limit) = budget.exceeded() {
        return Err(EVMError::Custom(trace_memory_limit_exceeded(limit)));
    }
    Ok(result)
}

pub(crate) fn inspect_with_citrea_handler<'a, C, I>(
    db: EvmDb<'a, C>,
    config_env: CfgEnv,
    block_env: BlockEnv,
    tx_env: TxEnv,
    l1_fee_rate: u128,
    inspector: I,
) -> Result<(ResultAndState, TxInfo), EVMError<DBError>>
where
    C: sov_modules_api::Context,
    I: for<'c> Inspector<CitreaContext<'c, EvmDb<'a, C>>>,
{
    let mut ext = CitreaChain::new(l1_fee_rate);
    let tmp_hash: TxHash = b"hash_of_an_ephemeral_transaction".into();

    ext.set_current_tx_hash(&tmp_hash);

    let mut journal = Journal::new(db);
    journal.set_spec_id(config_env.spec());
    let mut evm = Context {
        block: block_env,
        cfg: config_env,
        chain: &mut ext,
        tx: tx_env,
        error: Ok(()),
        journaled_state: journal,
    }
    .build_citrea_with_inspector(inspector);

    let result_and_state = evm.inspect_replay()?;
    let tx_info = ext.get_tx_info(&tmp_hash).unwrap_or_default(); // default 0 in case tx was unsuccessful;

    Ok((result_and_state, tx_info))
}

/// Like [`inspect_with_citrea_handler`], but uses the non-inspecting [`ExecuteEvm::replay`] path.
pub(crate) fn execute_with_citrea_handler<'a, C>(
    db: EvmDb<'a, C>,
    config_env: CfgEnv,
    block_env: BlockEnv,
    tx_env: TxEnv,
    l1_fee_rate: u128,
) -> Result<(ResultAndState, TxInfo), EVMError<DBError>>
where
    C: sov_modules_api::Context,
{
    let mut ext = CitreaChain::new(l1_fee_rate);
    let tmp_hash: TxHash = b"hash_of_an_ephemeral_transaction".into();

    ext.set_current_tx_hash(&tmp_hash);

    let mut journal = Journal::new(db);
    journal.set_spec_id(config_env.spec());
    let mut evm = Context {
        block: block_env,
        cfg: config_env,
        chain: &mut ext,
        tx: tx_env,
        error: Ok(()),
        journaled_state: journal,
    }
    .build_citrea();

    let result_and_state = evm.replay()?;
    let tx_info = ext.get_tx_info(&tmp_hash).unwrap_or_default(); // default 0 in case tx was unsuccessful;

    Ok((result_and_state, tx_info))
}

/// https://github.com/paradigmxyz/reth/blob/332e412a0f8d34ff2bbb7e07921f8cacdcf69d64/crates/rpc/rpc/src/eth/revm_utils.rs#L403
/// Calculates the caller gas allowance.
///
/// `allowance = (account.balance - tx.value) / tx.gas_price`
///
/// Returns an error if the caller has insufficient funds.
/// Caution: This assumes non-zero `env.gas_price`. Otherwise, zero allowance will be returned.
pub(crate) fn caller_gas_allowance(balance: U256, value: U256, gas_price: U256) -> EthResult<U256> {
    Ok(balance
        // Subtract transferred value from the caller balance.
        .checked_sub(value)
        // Return error if the caller has insufficient funds.
        .ok_or_else(|| RpcInvalidTransactionError::InsufficientFunds {
            cost: value,
            balance,
        })?
        // Calculate the amount of gas the caller can afford with the specified gas price.
        .checked_div(gas_price)
        // This will be 0 if gas price is 0. It is fine, because we check it before.
        .unwrap_or_default())
}
