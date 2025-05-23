use std::collections::BTreeMap;
use std::sync::Arc;

use alloy_primitives::{BlockHash, TxHash};
use alloy_rpc_types::BlockNumberOrTag;
use alloy_rpc_types_trace::geth::{
    CallConfig, CallFrame, FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerConfig,
    GethDebugTracerType, GethDebugTracingOptions, GethTrace, NoopFrame, TraceResult,
};
use alloy_rpc_types_trace::parity::{
    Action, CallAction, CallOutput, CallType, CreateAction, CreateOutput, CreationMethod,
    LocalizedTransactionTrace, SelfdestructAction, TraceOutput, TransactionTrace,
};
use citrea_evm::Evm;
use citrea_primitives::forks::fork_from_block_number;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::{PendingSubscriptionSink, SubscriptionMessage};
use reth_rpc_eth_types::error::EthApiError;
use sov_modules_api::WorkingSet;
use sov_rollup_interface::services::da::DaService;
use tracing::error;

use crate::ethereum::Ethereum;

pub async fn handle_debug_trace_chain<C: sov_modules_api::Context, Da: DaService>(
    start_block: BlockNumberOrTag,
    end_block: BlockNumberOrTag,
    opts: Option<GethDebugTracingOptions>,
    pending: PendingSubscriptionSink,
    ethereum: Arc<Ethereum<C, Da>>,
) {
    // start block is exclusive, hence latest is not supported
    let BlockNumberOrTag::Number(start_block) = start_block else {
        pending.reject(EthApiError::Unsupported(
            "Latest, earliest, pending, safe and finalized are not supported for traceChain start block",
        )).await;
        return;
    };

    let mut working_set = WorkingSet::new(ethereum.storage.clone());
    let evm = Evm::<C>::default();
    let latest_block_number: u64 = evm
        .block_number(&mut working_set)
        .expect("Expected at least one block")
        .saturating_to();
    let end_block = match end_block {
        BlockNumberOrTag::Number(end_block) => {
            if end_block > latest_block_number {
                pending
                    .reject(EthApiError::HeaderNotFound(end_block.into()))
                    .await;
                return;
            }
            end_block
        }
        BlockNumberOrTag::Latest => latest_block_number,
        _ => {
            pending
                .reject(EthApiError::Unsupported(
                    "Earliest, pending, safe and finalized are not supported for traceChain end block",
                ))
                .await;
            return;
        }
    };

    if start_block >= end_block {
        pending.reject(EthApiError::InvalidBlockRange).await;
        return;
    }

    let subscription = pending.accept().await.unwrap();

    // This task will be fetching and sending to the subscription sink the list of traces
    // for each block in the requested range. This task does not run indefinitely and therefore does
    // not need to be managed by the SubscriptionManager.
    tokio::spawn(async move {
        for block_number in start_block + 1..=end_block {
            let mut working_set = WorkingSet::new(ethereum.storage.clone());
            let traces = debug_trace_by_block_number(
                block_number,
                None,
                None,
                &ethereum,
                &evm,
                &mut working_set,
                opts.clone(),
            );
            match traces {
                Ok(traces) => {
                    let msg = SubscriptionMessage::new(
                        subscription.method_name(),
                        subscription.subscription_id(),
                        &traces,
                    )
                    .unwrap();
                    let Ok(_) = subscription.send(msg).await else {
                        return;
                    };
                }
                Err(err) => {
                    error!(
                        "Failed to get traces of block {} in traceChain: {}",
                        block_number, err
                    );

                    let msg = SubscriptionMessage::new(
                        subscription.method_name(),
                        subscription.subscription_id(),
                        &"Internal error",
                    )
                    .unwrap();
                    let _ = subscription.send(msg).await;
                    return;
                }
            };
        }
    });
}

pub fn debug_trace_by_block_number<C: sov_modules_api::Context, Da: DaService>(
    block_number: u64,
    tx_hash: Option<TxHash>,
    trace_idx: Option<usize>,
    ethereum: &Ethereum<C, Da>,
    evm: &Evm<C>,
    working_set: &mut WorkingSet<C::Storage>,
    opts: Option<GethDebugTracingOptions>,
) -> Result<Vec<TraceResult>, ErrorObjectOwned> {
    // If tracer option is not specified, or it is JsTracer, then do not check cache or insert cache, just perform the operation
    // Skip cache from JsTracer, MuxTracer and PreStateTracer
    let skip_cache = opts.as_ref().is_none_or(|o| {
        o.tracer.as_ref().is_none_or(|inner| match inner {
            GethDebugTracerType::JsTracer(_) => true,
            GethDebugTracerType::BuiltInTracer(bit) => match bit {
                GethDebugBuiltInTracerType::MuxTracer
                | GethDebugBuiltInTracerType::PreStateTracer => true,
                _ => false,
            },
        })
    });
    if skip_cache {
        let mut traces = evm.trace_block_transactions_by_number(
            block_number,
            opts,
            trace_idx,
            working_set,
            fork_from_block_number,
        )?;
        return match trace_idx {
            Some(idx) => Ok(vec![traces.remove(idx)]),
            None => Ok(traces),
        };
    }
    let block_hash = evm.blockhash_get(block_number, working_set);

    let requested_opts = opts.unwrap();
    let tracer_type = requested_opts.tracer.unwrap();
    let tracer_config = requested_opts.tracer_config;

    if let Some(traces) = ethereum.trace_cache.lock().unwrap().get(&block_number) {
        // If traces are found in cache convert them to specified opts and then return
        let traces = match trace_idx {
            Some(idx) => vec![traces[idx].clone()],
            None => traces.to_vec(),
        };
        let traces = get_traces_with_requested_tracer_and_config(
            traces,
            tracer_type,
            tracer_config,
            block_number,
            block_hash,
            tx_hash,
            trace_idx,
        )?;
        return Ok(traces);
    }

    let cache_options = create_trace_cache_opts();

    let mut traces = evm.trace_block_transactions_by_number(
        block_number,
        Some(cache_options),
        None,
        working_set,
        fork_from_block_number,
    )?;
    ethereum
        .trace_cache
        .lock()
        .unwrap()
        .insert(block_number, traces.clone());

    // Convert the traces to the requested tracer and config
    let traces = match trace_idx {
        Some(idx) => vec![traces.remove(idx)],
        None => traces,
    };
    let traces = get_traces_with_requested_tracer_and_config(
        traces,
        tracer_type,
        tracer_config,
        block_number,
        block_hash,
        tx_hash,
        trace_idx,
    )?;

    Ok(traces)
}

fn apply_call_config(call_frame: CallFrame, call_config: CallConfig) -> CallFrame {
    // let only_top_call = call_config.only_top_call.unwrap_or();
    let mut new_call_frame = call_frame.clone();
    if let Some(true) = call_config.only_top_call {
        new_call_frame.calls = vec![];
    }
    if !call_config.with_log.unwrap_or(false) {
        remove_logs_from_call_frame(&mut vec![new_call_frame.clone()]);
    }
    new_call_frame
}

fn remove_logs_from_call_frame(call_frame: &mut Vec<CallFrame>) {
    for frame in call_frame {
        frame.logs = vec![];
        remove_logs_from_call_frame(&mut frame.calls);
    }
}

fn get_traces_with_requested_tracer_and_config(
    traces: Vec<TraceResult>,
    tracer: GethDebugTracerType,
    tracer_config: GethDebugTracerConfig,
    block_number: u64,
    block_hash: Option<BlockHash>,
    tx_hash: Option<TxHash>,
    tx_index: Option<usize>,
) -> Result<Vec<TraceResult>, EthApiError> {
    // This can be only CallConfig or PreStateConfig if it is not CallConfig return Error for now

    let mut new_traces = vec![];
    match tracer {
        GethDebugTracerType::BuiltInTracer(builtin_tracer) => {
            match builtin_tracer {
                GethDebugBuiltInTracerType::CallTracer => {
                    // Apply the call config to the traces
                    let call_config =
                        GethDebugTracerConfig::into_call_config(tracer_config).unwrap_or_default();
                    // if call config is the same in the cache then do not process again and return early
                    match call_config {
                        CallConfig {
                            only_top_call: None,
                            with_log: Some(true),
                        }
                        | CallConfig {
                            only_top_call: Some(false),
                            with_log: Some(true),
                        } => {
                            return Ok(traces);
                        }
                        _ => {
                            traces.into_iter().for_each(|trace| {
                                if let TraceResult::Success {
                                    result: GethTrace::CallTracer(call_frame),
                                    tx_hash,
                                } = trace
                                {
                                    let new_call_frame =
                                        apply_call_config(call_frame.clone(), call_config);
                                    new_traces.push(TraceResult::new_success(
                                        GethTrace::CallTracer(new_call_frame),
                                        tx_hash,
                                    ));
                                }
                            });
                        }
                    }
                    Ok(new_traces)
                }
                GethDebugBuiltInTracerType::FlatCallTracer => {
                    let mut localized_call_frames = vec![];
                    for trace in traces {
                        if let TraceResult::Success {
                            result: GethTrace::CallTracer(call_frame),
                            tx_hash,
                        } = trace
                        {
                            let new_flat_call_frame = convert_call_trace_into_flatcall_frame(
                                call_frame,
                                Some(block_number),
                                block_hash,
                                tx_hash,
                                tx_index,
                            )?;
                            localized_call_frames.push(new_flat_call_frame);
                        }
                    }
                    new_traces.push(TraceResult::new_success(
                        GethTrace::FlatCallTracer(localized_call_frames),
                        tx_hash,
                    ));
                    Ok(new_traces)
                }
                GethDebugBuiltInTracerType::PreStateTracer => Ok(traces),
                GethDebugBuiltInTracerType::FourByteTracer => {
                    traces.into_iter().for_each(|trace| {
                        if let TraceResult::Success {
                            result: GethTrace::CallTracer(call_frame),
                            tx_hash,
                        } = trace
                        {
                            let four_byte_frame =
                                convert_call_trace_into_4byte_frame(vec![call_frame]);
                            new_traces.push(TraceResult::new_success(
                                GethTrace::FourByteTracer(four_byte_frame),
                                tx_hash,
                            ));
                        }
                    });
                    Ok(new_traces)
                }
                GethDebugBuiltInTracerType::NoopTracer => Ok(vec![TraceResult::new_success(
                    GethTrace::NoopTracer(NoopFrame::default()),
                    None,
                )]),
                _ => Err(EthApiError::Unsupported("This tracer is not supported")),
            }
        }
        GethDebugTracerType::JsTracer(_code) => {
            unimplemented!(
                "Converting frames into js traces not implemented, and should be handled in evm"
            )
        }
    }
}

fn convert_call_trace_into_flatcall_frame(
    call_frame: CallFrame,
    block_number: Option<u64>,
    block_hash: Option<BlockHash>,
    tx_hash: Option<TxHash>,
    tx_index: Option<usize>,
) -> Result<LocalizedTransactionTrace, EthApiError> {
    let trace = match call_frame.typ.as_str() {
        "CREATE" | "CREATE2" => TransactionTrace {
            action: Action::Create(CreateAction {
                from: call_frame.from,
                gas: call_frame.gas.saturating_to(),
                init: call_frame.input,
                value: call_frame.value.expect("Invalid value set for create call"),
                creation_method: match call_frame.typ.as_str() {
                    "CREATE" => CreationMethod::Create,
                    "CREATE2" => CreationMethod::Create2,
                    &_ => {
                        return Err(EthApiError::Unsupported("Unsupported call type"));
                    }
                },
            }),
            error: call_frame.error,
            result: Some(TraceOutput::Create(CreateOutput {
                address: call_frame.to.expect("To field should be set"),
                code: call_frame.output.expect("Code should be set"),
                gas_used: call_frame.gas_used.saturating_to(),
            })),
            subtraces: call_frame.calls.len(),
            trace_address: vec![],
        },
        "SELFDESTRUCT" => TransactionTrace {
            action: Action::Selfdestruct(SelfdestructAction {
                address: call_frame.from,
                balance: call_frame.value.expect("Value should be set"),
                refund_address: call_frame.to.expect("To field should be set"),
            }),
            error: call_frame.error,
            result: Some(TraceOutput::Create(CreateOutput {
                address: call_frame.to.expect("To field should be set"),
                code: call_frame.output.expect("Code should be set"),
                gas_used: call_frame.gas_used.saturating_to(),
            })),
            subtraces: call_frame.calls.len(),
            trace_address: vec![],
        },
        "CALL" | "STATICCALL" | "CALLCODE" | "DELEGATECALL" => TransactionTrace {
            action: Action::Call(CallAction {
                from: call_frame.from,
                call_type: match call_frame.typ.to_lowercase().as_str() {
                    "call" => CallType::Call,
                    "staticcall" => CallType::StaticCall,
                    "callcode" => CallType::CallCode,
                    "delegatecall" => CallType::DelegateCall,
                    &_ => {
                        return Err(EthApiError::Unsupported("Unsupported call type"));
                    }
                },
                gas: call_frame.gas.saturating_to(),
                input: call_frame.input,
                to: call_frame.to.expect("To field should be set"),
                value: call_frame.value.expect("Value should be set"),
            }),
            error: call_frame.error,
            result: Some(TraceOutput::Call(CallOutput {
                gas_used: call_frame.gas_used.saturating_to(),
                output: call_frame.output.expect("output should be set"),
            })),
            subtraces: call_frame.calls.len(),
            trace_address: vec![],
        },
        _ => {
            return Err(EthApiError::Unsupported("Unsupported call frame"));
        }
    };

    Ok(LocalizedTransactionTrace {
        trace,
        block_hash,
        block_number,
        transaction_hash: tx_hash,
        transaction_position: tx_index.map(|i| i as u64),
    })
}

fn convert_call_trace_into_4byte_frame(call_frames: Vec<CallFrame>) -> FourByteFrame {
    FourByteFrame(convert_call_trace_into_4byte_map(
        call_frames,
        BTreeMap::new(),
    ))
}

fn convert_call_trace_into_4byte_map(
    call_frames: Vec<CallFrame>,
    mut four_byte_map: BTreeMap<String, u64>,
) -> BTreeMap<String, u64> {
    // For each input in each call
    // get the first 4 bytes, get the size of the input
    // the key is : "<first 4 bytes>-<size of the input>"
    // value is the occurence of the key
    for call_frame in call_frames {
        let input = call_frame.input;
        // If this is a function call (function selector is 4 bytes long)
        if input.len() >= 4 {
            let input_size = input.0.len() - 4;
            let four_byte = &input.to_string()[2..10]; // Ignore the 0x
            let key = format!("{}-{}", four_byte, input_size);
            let count = four_byte_map.entry(key).or_insert(0);
            *count += 1;
        }
        four_byte_map = convert_call_trace_into_4byte_map(call_frame.calls, four_byte_map);
    }
    four_byte_map
}

fn create_trace_cache_opts() -> GethDebugTracingOptions {
    // Get the traces with call tracer onlytopcall false and withlog true and always cache this way
    let mut call_config_map = serde_json::Map::new();
    call_config_map.insert("only_top_call".to_string(), serde_json::Value::Bool(false));
    call_config_map.insert("with_log".to_string(), serde_json::Value::Bool(true));
    let call_config = serde_json::Value::Object(call_config_map);
    GethDebugTracingOptions {
        tracer: Some(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::CallTracer,
        )),
        tracer_config: GethDebugTracerConfig(call_config),
        ..Default::default()
    }
}
