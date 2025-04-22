use alloy_primitives::{TxHash, U256};
use alloy_rpc_types_trace::geth::{
    FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingCallOptions,
    GethDebugTracingOptions, GethTrace, NoopFrame,
};
use reth_rpc_eth_types::error::{EthApiError, EthResult, RpcInvalidTransactionError};
use revm::context::result::{EVMError, ResultAndState};
use revm::context::{Cfg, CfgEnv, JournalTr, TxEnv};
use revm::{Context, InspectEvm, Inspector, Journal};
use revm_inspectors::tracing::js::JsInspector;
use revm_inspectors::tracing::{
    FourByteInspector, TracingInspector, TracingInspectorConfig, TransactionContext,
};

use crate::db::{AccountExistsProvider, DBError};
use crate::evm::db::immutable::EvmDbRef;
use crate::evm::db::EvmDb;
use crate::handler::{CitreaBuilder, CitreaChain, CitreaChainExt, CitreaContext, TxInfo};
use crate::rpc_helpers::*;

pub(crate) fn trace_call<C: sov_modules_api::Context>(
    opts: GethDebugTracingCallOptions,
    config_env: CfgEnv,
    mut block_env: BlockEnv,
    tx_env: TxEnv,
    db: &mut EvmDb<'_, C>,
    l1_fee_rate: u128,
) -> EthResult<GethTrace> {
    let GethDebugTracingCallOptions {
        tracing_options,
        state_overrides,
        block_overrides,
    } = opts;

    if let Some(state_overrides) = state_overrides {
        apply_state_overrides(state_overrides, db)?;
    }

    if let Some(mut block_overrides) = block_overrides {
        apply_block_overrides(&mut block_env, &mut block_overrides, db);
    }

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
                    )?;
                    return Ok(FourByteFrame::from(inspector).into());
                }
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config
                        .into_call_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;

                    let mut inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_call_config(&call_config),
                    );

                    let res = trace_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        None,
                        l1_fee_rate,
                        &mut inspector,
                    )?;
                    let frame = inspector
                        .into_geth_builder()
                        .geth_call_traces(call_config, res.result.gas_used());
                    Ok(frame.into())
                }
                GethDebugBuiltInTracerType::PreStateTracer => {
                    // Requires DatabaseRef trait
                    // meaning we need a readonly state to implement this
                    Err(EthApiError::Unsupported("PreStateTracer"))
                }
                GethDebugBuiltInTracerType::NoopTracer => Ok(NoopFrame::default().into()),
                GethDebugBuiltInTracerType::MuxTracer => Err(EthApiError::Unsupported("MuxTracer")),
                GethDebugBuiltInTracerType::FlatCallTracer => {
                    Err(EthApiError::Unsupported("FlatCallTracer"))
                }
            },
            GethDebugTracerType::JsTracer(code) => {
                let config = tracer_config.into_json();
                let mut inspector = JsInspector::new(code, config)
                    .map_err(|e| EthApiError::InternalJsTracerError(e.to_string()))?;

                let mut db_ref = EvmDbRef::new(db);
                let result_and_state = trace_citrea(
                    &mut db_ref,
                    config_env.clone(),
                    block_env.clone(),
                    tx_env.clone(),
                    None,
                    l1_fee_rate,
                    &mut inspector,
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
    )?;
    let gas_used = res.result.gas_used();
    let return_value = res.result.into_output().unwrap_or_default();
    let frame = inspector
        .into_geth_builder()
        .geth_traces(gas_used, return_value, config);

    Ok(frame.into())
}

pub(crate) fn trace_transaction<C: sov_modules_api::Context>(
    opts: GethDebugTracingOptions,
    config_env: CfgEnv,
    block_env: BlockEnv,
    tx_env: TxEnv,
    tx_hash: &TxHash,
    db: &mut EvmDb<'_, C>,
    l1_fee_rate: u128,
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
                    )?;
                    return Ok((FourByteFrame::from(inspector).into(), res.state));
                }
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config
                        .into_call_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;
                    let mut inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_config(&config)
                            .set_record_logs(call_config.with_log.unwrap_or_default()),
                    );
                    let res = trace_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        Some(tx_hash),
                        l1_fee_rate,
                        &mut inspector,
                    )?;
                    let frame = inspector
                        .into_geth_builder()
                        .geth_call_traces(call_config, res.result.gas_used());
                    Ok((frame.into(), res.state))
                }
                GethDebugBuiltInTracerType::PreStateTracer => {
                    // Requires DatabaseRef trait
                    // meaning we need a readonly state to implement this
                    Err(EthApiError::Unsupported("PreStateTracer"))
                }
                GethDebugBuiltInTracerType::NoopTracer => {
                    Ok((NoopFrame::default().into(), Default::default()))
                }
                GethDebugBuiltInTracerType::MuxTracer => Err(EthApiError::Unsupported("MuxTracer")),
                GethDebugBuiltInTracerType::FlatCallTracer => {
                    Err(EthApiError::Unsupported("FlatCallTracer"))
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
    )?;
    let gas_used = res.result.gas_used();
    let return_value = res.result.into_output().unwrap_or_default();
    let frame = inspector
        .into_geth_builder()
        .geth_traces(gas_used, return_value, config);

    Ok((frame.into(), res.state))
}

/// Executes the [Env] against the given [Database] without committing state changes.
fn trace_citrea<DB, I>(
    db: DB,
    config_env: CfgEnv,
    block_env: BlockEnv,
    tx_env: TxEnv,
    tx_hash: Option<&TxHash>,
    l1_fee_rate: u128,
    inspector: I,
) -> Result<ResultAndState, EVMError<<DB as revm::Database>::Error>>
where
    DB: Database + AccountExistsProvider,
    I: for<'c> Inspector<CitreaContext<'c, DB>>,
{
    let mut ext = CitreaChain::new(l1_fee_rate);
    if let Some(tx_hash) = tx_hash {
        ext.set_current_tx_hash(tx_hash);
    }

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

    evm.inspect_replay()
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
