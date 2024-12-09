use std::collections::BTreeMap;
use std::sync::Arc;

#[cfg(feature = "local")]
use citrea_evm::Evm;
use jsonrpsee::types::{ErrorObjectOwned, ParamsSequence};
use jsonrpsee::{PendingSubscriptionSink, SubscriptionMessage};
use reth_primitives::BlockNumberOrTag;
use reth_rpc_eth_types::error::EthApiError;
use reth_rpc_types::trace::geth::{
    CallConfig, CallFrame, FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerConfig,
    GethDebugTracerType, GethDebugTracingOptions, GethTrace, NoopFrame,
};
use sov_modules_api::WorkingSet;
use sov_rollup_interface::services::da::DaService;
use tracing::error;

use crate::ethereum::Ethereum;

pub async fn handle_debug_trace_chain<C: sov_modules_api::Context, Da: DaService>(
    mut params: ParamsSequence<'_>,
    pending: PendingSubscriptionSink,
    ethereum: Arc<Ethereum<C, Da>>,
) {
    let start_block: BlockNumberOrTag = match params.next() {
        Ok(v) => v,
        Err(err) => {
            pending.reject(err).await;
            return;
        }
    };
    let end_block: BlockNumberOrTag = match params.next() {
        Ok(v) => v,
        Err(err) => {
            pending.reject(err).await;
            return;
        }
    };

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
                pending.reject(EthApiError::UnknownBlockNumber).await;
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

    let opts: Option<GethDebugTracingOptions> = match params.optional_next() {
        Ok(v) => v,
        Err(err) => {
            pending.reject(err).await;
            return;
        }
    };

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
    trace_idx: Option<usize>,
    ethereum: &Ethereum<C, Da>,
    evm: &Evm<C>,
    working_set: &mut WorkingSet<C::Storage>,
    opts: Option<GethDebugTracingOptions>,
) -> Result<Vec<GethTrace>, ErrorObjectOwned> {
    // If opts is None or if opts.tracer is None, then do not check cache or insert cache, just perform the operation
    if opts.as_ref().map_or(true, |o| o.tracer.is_none()) {
        let traces =
            evm.trace_block_transactions_by_number(block_number, opts, trace_idx, working_set)?;
        return match trace_idx {
            Some(idx) => Ok(vec![traces[idx].clone()]),
            None => Ok(traces),
        };
    }

    let requested_opts = opts.unwrap();
    let tracer_type = requested_opts.tracer.unwrap();
    let tracer_config = requested_opts.tracer_config;

    if let Some(traces) = ethereum.trace_cache.lock().unwrap().get(&block_number) {
        // If traces are found in cache convert them to specified opts and then return
        let traces = match trace_idx {
            Some(idx) => vec![traces[idx].clone()],
            None => traces.to_vec(),
        };
        let traces =
            get_traces_with_requested_tracer_and_config(traces, tracer_type, tracer_config)?;
        return Ok(traces);
    }

    let cache_options = create_trace_cache_opts();
    let traces = evm.trace_block_transactions_by_number(
        block_number,
        Some(cache_options),
        None,
        working_set,
    )?;
    ethereum
        .trace_cache
        .lock()
        .unwrap()
        .insert(block_number, traces.clone());

    // Convert the traces to the requested tracer and config
    let traces = match trace_idx {
        Some(idx) => vec![traces[idx].clone()],
        None => traces,
    };
    let traces = get_traces_with_requested_tracer_and_config(traces, tracer_type, tracer_config)?;

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
    traces: Vec<GethTrace>,
    tracer: GethDebugTracerType,
    tracer_config: GethDebugTracerConfig,
) -> Result<Vec<GethTrace>, EthApiError> {
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
                                if let GethTrace::CallTracer(call_frame) = trace {
                                    let new_call_frame =
                                        apply_call_config(call_frame.clone(), call_config);
                                    new_traces.push(GethTrace::CallTracer(new_call_frame));
                                }
                            });
                        }
                    }
                    Ok(new_traces)
                }
                GethDebugBuiltInTracerType::FourByteTracer => {
                    traces.into_iter().for_each(|trace| {
                        if let GethTrace::CallTracer(call_frame) = trace {
                            let four_byte_frame =
                                convert_call_trace_into_4byte_frame(vec![call_frame]);
                            new_traces.push(GethTrace::FourByteTracer(four_byte_frame));
                        }
                    });
                    Ok(new_traces)
                }
                GethDebugBuiltInTracerType::NoopTracer => {
                    Ok(vec![GethTrace::NoopTracer(NoopFrame::default())])
                }
                _ => Err(EthApiError::Unsupported("This tracer is not supported")),
            }
        }
        GethDebugTracerType::JsTracer(_code) => {
            // This also requires DatabaseRef trait
            // Implement after readonly state is implemented
            Err(EthApiError::Unsupported("JsTracer"))
        }
    }
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
