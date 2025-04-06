use alloy_primitives::{TxHash, U256};
use alloy_rpc_types_trace::geth::{
    FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingCallOptions,
    GethDebugTracingOptions, GethTrace, NoopFrame,
};
use reth_rpc_eth_types::error::{EthApiError, EthResult, RpcInvalidTransactionError};
use revm::primitives::{BlockEnv, CfgEnvWithHandlerCfg, EVMError, ResultAndState, TxEnv};
use revm::{inspector_handle_register, Inspector};
use revm_inspectors::tracing::js::JsInspector;
use revm_inspectors::tracing::{
    FourByteInspector, TracingInspector, TracingInspectorConfig, TransactionContext,
};

use crate::db::DBError;
use crate::evm::db::immutable::EvmDbRef;
use crate::evm::db::EvmDb;
use crate::handler::{citrea_handle_register, CitreaExternalExt, TracingCitreaExternal, TxInfo};
use crate::rpc_helpers::*;

pub(crate) fn trace_call<C: sov_modules_api::Context>(
    opts: GethDebugTracingCallOptions,
    config_env: CfgEnvWithHandlerCfg,
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
                    let inspector = FourByteInspector::default();

                    let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);
                    let _ = trace_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        None,
                        &mut citrea_inspector,
                    )?;
                    return Ok(FourByteFrame::from(citrea_inspector.inspector).into());
                }
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config
                        .into_call_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;

                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_call_config(&call_config),
                    );
                    let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);

                    let res = trace_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        None,
                        &mut citrea_inspector,
                    )?;
                    let frame = citrea_inspector
                        .inspector
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

                let inspector = JsInspector::new(code, config)
                    .map_err(|e| EthApiError::InternalJsTracerError(e.to_string()))?;
                let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);

                let mut db_ref = EvmDbRef::new(db);
                let result_and_state = js_trace_citrea(
                    &mut db_ref,
                    config_env.clone(),
                    block_env.clone(),
                    tx_env.clone(),
                    None,
                    &mut citrea_inspector,
                )?;

                let env = revm::primitives::Env {
                    cfg: config_env.cfg_env,
                    block: block_env,
                    tx: tx_env,
                };

                let json_value = citrea_inspector
                    .inspector
                    .json_result(result_and_state, &env, &db_ref)
                    .map_err(|e| EthApiError::InternalJsTracerError(e.to_string()))?;
                Ok(GethTrace::JS(json_value))
            }
        };
    }

    // default structlog tracer
    let inspector_config = TracingInspectorConfig::from_geth_config(&config);

    let inspector = TracingInspector::new(inspector_config);
    let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);

    let res = trace_citrea(
        db,
        config_env,
        block_env,
        tx_env,
        None,
        &mut citrea_inspector,
    )?;
    let gas_used = res.result.gas_used();
    let return_value = res.result.into_output().unwrap_or_default();
    let frame =
        citrea_inspector
            .inspector
            .into_geth_builder()
            .geth_traces(gas_used, return_value, config);

    Ok(frame.into())
}

pub(crate) fn trace_transaction<C: sov_modules_api::Context>(
    opts: GethDebugTracingOptions,
    config_env: CfgEnvWithHandlerCfg,
    block_env: BlockEnv,
    tx_env: TxEnv,
    tx_hash: &TxHash,
    db: &mut EvmDb<'_, C>,
    l1_fee_rate: u128,
) -> EthResult<(GethTrace, revm::primitives::state::EvmState)> {
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
                    let inspector = FourByteInspector::default();
                    let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);
                    let res = trace_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        Some(tx_hash),
                        &mut citrea_inspector,
                    )?;
                    return Ok((
                        FourByteFrame::from(citrea_inspector.inspector).into(),
                        res.state,
                    ));
                }
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config
                        .into_call_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;
                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_config(&config)
                            .set_record_logs(call_config.with_log.unwrap_or_default()),
                    );
                    let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);
                    let res = trace_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        Some(tx_hash),
                        &mut citrea_inspector,
                    )?;
                    let frame = citrea_inspector
                        .inspector
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
                let inspector =
                    JsInspector::with_transaction_context(code, config, transaction_context)
                        .map_err(|e| EthApiError::InternalJsTracerError(e.to_string()))?;
                let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);

                let mut db_ref = EvmDbRef::new(db);
                let result_and_state = js_trace_citrea(
                    &mut db_ref,
                    config_env.clone(),
                    block_env.clone(),
                    tx_env.clone(),
                    Some(tx_hash),
                    &mut citrea_inspector,
                )?;
                let state = result_and_state.state.clone();

                let env = revm::primitives::Env {
                    cfg: config_env.cfg_env,
                    block: block_env,
                    tx: tx_env,
                };

                let json_value = citrea_inspector
                    .inspector
                    .json_result(result_and_state, &env, &db_ref)
                    .map_err(|e| EthApiError::InternalJsTracerError(e.to_string()))?;
                Ok((GethTrace::JS(json_value), state))
            }
        };
    }

    // default structlog tracer
    let inspector_config = TracingInspectorConfig::from_geth_config(&config);

    let inspector = TracingInspector::new(inspector_config);
    let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);

    let res = trace_citrea(
        db,
        config_env,
        block_env,
        tx_env,
        Some(tx_hash),
        &mut citrea_inspector,
    )?;
    let gas_used = res.result.gas_used();
    let return_value = res.result.into_output().unwrap_or_default();
    let frame =
        citrea_inspector
            .inspector
            .into_geth_builder()
            .geth_traces(gas_used, return_value, config);

    Ok((frame.into(), res.state))
}

/// Executes the [Env] against the given [Database] without committing state changes.
fn trace_citrea<'a, 'b, C, I>(
    db: &'b mut EvmDb<'a, C>,
    config_env: CfgEnvWithHandlerCfg,
    block_env: BlockEnv,
    tx_env: TxEnv,
    tx_hash: Option<&TxHash>,
    inspector: I,
) -> Result<ResultAndState, EVMError<DBError>>
where
    C: sov_modules_api::Context,
    I: Inspector<&'b mut EvmDb<'a, C>>,
    I: CitreaExternalExt,
{
    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(inspector)
        .with_cfg_env_with_handler_cfg(config_env)
        .with_block_env(block_env)
        .with_tx_env(tx_env)
        .append_handler_register_box(citrea_handle_register())
        .append_handler_register(inspector_handle_register)
        .build();

    if let Some(tx_hash) = tx_hash {
        evm.context.external.set_current_tx_hash(tx_hash);
    }

    evm.transact()
}

fn js_trace_citrea<'a, 'b, 'c, C, I>(
    db: &'c mut EvmDbRef<'a, 'b, C>,
    config_env: CfgEnvWithHandlerCfg,
    block_env: BlockEnv,
    tx_env: TxEnv,
    tx_hash: Option<&TxHash>,
    inspector: I,
) -> Result<ResultAndState, EVMError<DBError>>
where
    C: sov_modules_api::Context,
    I: Inspector<&'c mut EvmDbRef<'a, 'b, C>>,
    I: CitreaExternalExt,
{
    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(inspector)
        .with_cfg_env_with_handler_cfg(config_env)
        .with_block_env(block_env)
        .with_tx_env(tx_env)
        .append_handler_register_box(citrea_handle_register())
        .append_handler_register(inspector_handle_register)
        .build();

    if let Some(tx_hash) = tx_hash {
        evm.context.external.set_current_tx_hash(tx_hash);
    }

    evm.transact()
}

pub(crate) fn inspect_with_citrea_handle<'a, C, I>(
    db: EvmDb<'a, C>,
    config_env: CfgEnvWithHandlerCfg,
    block_env: BlockEnv,
    tx_env: TxEnv,
    ext: &mut I,
) -> Result<(ResultAndState, TxInfo), EVMError<DBError>>
where
    C: sov_modules_api::Context,
    I: Inspector<EvmDb<'a, C>>,
    I: CitreaExternalExt,
{
    let tmp_hash: TxHash = b"hash_of_an_ephemeral_transaction".into();

    ext.set_current_tx_hash(&tmp_hash);

    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(ext)
        .with_cfg_env_with_handler_cfg(config_env)
        .with_block_env(block_env)
        .with_tx_env(tx_env)
        .append_handler_register_box(citrea_handle_register())
        .append_handler_register(inspector_handle_register)
        .build();

    let result_and_state = evm.transact()?;
    let tx_info = evm
        .context
        .external
        .get_tx_info(&tmp_hash)
        .unwrap_or_default(); // default 0 in case tx was unsuccessful
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
