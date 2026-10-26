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
use citrea_evm::{mb_to_bytes, trace_memory_limit_exceeded, Evm};
use citrea_primitives::forks::fork_from_block_number;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::{PendingSubscriptionSink, SubscriptionMessage};
use reth_rpc_eth_types::error::EthApiError;
use sov_modules_api::WorkingSet;
use sov_rollup_interface::services::da::DaService;
use tokio::sync::Semaphore;
use tracing::error;

use crate::ethereum::Ethereum;

#[allow(clippy::too_many_arguments)]
pub async fn handle_debug_trace_chain<C: sov_modules_api::Context, Da: DaService>(
    start_block: BlockNumberOrTag,
    end_block: BlockNumberOrTag,
    opts: Option<GethDebugTracingOptions>,
    pending: PendingSubscriptionSink,
    ethereum: Arc<Ethereum<C, Da>>,
    max_blocks: Option<u64>,
    enable_js_tracer: bool,
    trace_memory_limit_mb: u64,
    tracing_permits: Arc<Semaphore>,
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
    let max_blocks = max_blocks.unwrap_or(u64::MAX);

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
    if (end_block - start_block) > max_blocks {
        pending
            .reject(EthApiError::InvalidParams(format!(
                "Block range too large. Maximum allowed range is {max_blocks} blocks"
            )))
            .await;
        return;
    }

    let subscription = pending.accept().await.unwrap();

    // This task will be fetching and sending to the subscription sink the list of traces
    // for each block in the requested range. This task does not run indefinitely and therefore does
    // not need to be managed by the SubscriptionManager.
    tokio::spawn(async move {
        for block_number in start_block + 1..=end_block {
            // A permit per block, not one for the whole range: a long traceChain would otherwise
            // hold a tracing slot for its entire lifetime. There is no wait timeout here because a
            // subscription is long lived by nature, and the work runs on the blocking pool so it
            // does not occupy a runtime thread while it traces.
            let Ok(permit) = tracing_permits.clone().acquire_owned().await else {
                return;
            };
            let block_ethereum = ethereum.clone();
            let block_opts = opts.clone();
            let traces = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let evm = Evm::<C>::default();
                let mut working_set = WorkingSet::new(block_ethereum.storage.clone());
                debug_trace_by_block_number(
                    block_number,
                    None,
                    &block_ethereum,
                    &evm,
                    &mut working_set,
                    block_opts,
                    enable_js_tracer,
                    trace_memory_limit_mb,
                )
            })
            .await;

            let traces = match traces {
                Ok(traces) => traces,
                Err(err) => {
                    error!("traceChain task for block {} failed: {}", block_number, err);
                    return;
                }
            };

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

#[allow(clippy::too_many_arguments)]
pub fn debug_trace_by_block_number<C: sov_modules_api::Context, Da: DaService>(
    block_number: u64,
    trace_idx: Option<usize>,
    ethereum: &Ethereum<C, Da>,
    evm: &Evm<C>,
    working_set: &mut WorkingSet<C::Storage>,
    opts: Option<GethDebugTracingOptions>,
    enable_js_tracer: bool,
    trace_memory_limit_mb: u64,
) -> Result<Vec<TraceResult>, ErrorObjectOwned> {
    let is_js_tracer = matches!(
        opts.as_ref().and_then(|o| o.tracer.as_ref()),
        Some(GethDebugTracerType::JsTracer(_))
    );
    if is_js_tracer && !enable_js_tracer {
        return Err(EthApiError::Unsupported("JsTracer is disabled.").into());
    }
    // If tracer option is not specified, or it is JsTracer, then do not check cache or insert cache, just perform the operation
    // Skip cache from JsTracer, MuxTracer and PreStateTracer
    let skip_cache = opts.as_ref().is_none_or(|o| {
        o.tracer.as_ref().is_none_or(|inner| match inner {
            GethDebugTracerType::JsTracer(_) => true,
            GethDebugTracerType::BuiltInTracer(bit) => matches!(
                bit,
                GethDebugBuiltInTracerType::MuxTracer | GethDebugBuiltInTracerType::PreStateTracer
            ),
        })
    });
    if skip_cache {
        // with `trace_idx` set only that transaction is traced, so this is already just its trace
        return evm.trace_block_transactions_by_number(
            block_number,
            opts,
            trace_idx,
            working_set,
            &ethereum.ledger_db,
            fork_from_block_number,
            trace_memory_limit_mb,
        );
    }
    let block_hash = evm.blockhash_get(block_number, working_set);

    // `skip_cache` returned above unless the request names a built-in tracer, so both are set.
    let requested_opts = opts.unwrap();
    let tracer_type = requested_opts.tracer.unwrap();
    let tracer_config = requested_opts.tracer_config;

    if let Some(traces) = ethereum.trace_cache.lock().unwrap().get(&block_number) {
        // Cache hit: convert the cached whole-block callTracer{withLog:true} traces to the
        // requested tracer and config and return.
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
            trace_idx,
            trace_memory_limit_mb,
        )?;
        return Ok(traces);
    }

    // Cache miss on a single transaction. The cache only stores whole-block traces (the insert
    // below is guarded on `trace_idx.is_none()`), so don't build or cache the whole block here.
    // Build just this transaction's callTracer frame and convert it, exactly as the cache-hit and
    // whole-block paths do, so a single-transaction trace returns the same output as those paths:
    // running the requested native tracer here instead diverges on block/transaction metadata, gas
    // semantics and key formatting (FlatCall, fourByte). Only pay for logs when the request is
    // `callTracer{withLog:true}`: FlatCall/fourByte/noop/`callTracer{withLog:false}` never retain
    // them, so forcing `withLog` would charge the budget for logs the request's own output drops.
    if trace_idx.is_some() {
        let needs_logs = matches!(
            tracer_type,
            GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer)
        ) && GethDebugTracerConfig::into_call_config(tracer_config.clone())
            .unwrap_or_default()
            .with_log
            .unwrap_or(false);
        let build_opts = if needs_logs {
            create_trace_cache_opts()
        } else {
            GethDebugTracingOptions::call_tracer(CallConfig::default())
        };

        let traces = evm.trace_block_transactions_by_number(
            block_number,
            Some(build_opts),
            trace_idx,
            working_set,
            &ethereum.ledger_db,
            fork_from_block_number,
            trace_memory_limit_mb,
        )?;
        let traces = get_traces_with_requested_tracer_and_config(
            traces,
            tracer_type,
            tracer_config,
            block_number,
            block_hash,
            trace_idx,
            trace_memory_limit_mb,
        )?;
        return Ok(traces);
    }

    // Whole-block miss: build the callTracer{withLog:true} superset once, cache it, then convert
    // it to the requested tracer and config.
    let cache_options = create_trace_cache_opts();
    let traces = evm.trace_block_transactions_by_number(
        block_number,
        Some(cache_options),
        trace_idx,
        working_set,
        &ethereum.ledger_db,
        fork_from_block_number,
        trace_memory_limit_mb,
    )?;
    ethereum
        .trace_cache
        .lock()
        .unwrap()
        .insert(block_number, traces.clone());

    // Convert the traces to the requested tracer and config
    let traces = get_traces_with_requested_tracer_and_config(
        traces,
        tracer_type,
        tracer_config,
        block_number,
        block_hash,
        trace_idx,
        trace_memory_limit_mb,
    )?;

    Ok(traces)
}

fn apply_call_config(call_frame: CallFrame, call_config: CallConfig) -> CallFrame {
    let mut new_call_frame = call_frame;
    if let Some(true) = call_config.only_top_call {
        new_call_frame.calls = vec![];
    }
    if !call_config.with_log.unwrap_or(false) {
        // The caller hands us an owned frame (moved out of its own result), so strip the logs this
        // request did not ask for in place.
        remove_logs_from_call_frame(&mut new_call_frame);
    }
    new_call_frame
}

fn remove_logs_from_call_frame(call_frame: &mut CallFrame) {
    call_frame.logs = vec![];
    for frame in &mut call_frame.calls {
        remove_logs_from_call_frame(frame);
    }
}

/// If index is given as Some, traces is expected to be a single trace (trace for a single transaction in a block)
fn get_traces_with_requested_tracer_and_config(
    traces: Vec<TraceResult>,
    tracer: GethDebugTracerType,
    tracer_config: GethDebugTracerConfig,
    block_number: u64,
    block_hash: Option<BlockHash>,
    tx_index: Option<usize>,
    trace_memory_limit_mb: u64,
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
                                    let new_call_frame = apply_call_config(call_frame, call_config);
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
                    // Bound the whole flat-call response, not just its `traceAddress` vectors: the
                    // frames it takes over from the call frames count too. This path has no running
                    // usage (a cache hit never executed), so the response is measured against the
                    // full configured per-request limit before it is built (0 means unlimited).
                    if let Some(limit) =
                        (trace_memory_limit_mb != 0).then(|| mb_to_bytes(trace_memory_limit_mb))
                    {
                        let mut bytes = 0usize;
                        for trace in &traces {
                            if let TraceResult::Success {
                                result: GethTrace::CallTracer(call_frame),
                                ..
                            } = trace
                            {
                                bytes =
                                    bytes.saturating_add(flatcall_retained_bytes(call_frame, 0));
                            }
                        }
                        if bytes > limit {
                            return Err(EthApiError::EvmCustom(trace_memory_limit_exceeded(limit)));
                        }
                    }
                    for (index_from_vec, trace) in traces.into_iter().enumerate() {
                        if let TraceResult::Success {
                            result: GethTrace::CallTracer(call_frame),
                            tx_hash,
                        } = trace
                        {
                            let new_flat_call_frames = convert_call_trace_into_flatcall_frame(
                                call_frame,
                                vec![],
                                Some(block_number),
                                block_hash,
                                tx_hash,
                                tx_index.unwrap_or(index_from_vec),
                            )?;
                            new_traces.push(TraceResult::new_success(
                                GethTrace::FlatCallTracer(new_flat_call_frames),
                                tx_hash,
                            ));
                        }
                    }

                    Ok(new_traces)
                }
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
                // One empty frame per transaction, keeping its hash, as geth and reth do
                GethDebugBuiltInTracerType::NoopTracer => Ok(traces
                    .iter()
                    .map(|trace| {
                        TraceResult::new_success(
                            GethTrace::NoopTracer(NoopFrame::default()),
                            trace.tx_hash(),
                        )
                    })
                    .collect()),
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

/// Adapted from
/// https://github.com/ethereum/go-ethereum/blob/20ad4f500e7fafab93f6d94fa171a5c0309de6ce/eth/tracers/native/call_flat.go#L250
/// Bytes the flat-call conversion of `frame` would retain: per node, its
/// `LocalizedTransactionTrace`, the input, output and error moved over from the call frame, and a
/// `traceAddress` of length equal to its depth (root = 0). Allocation-free; mirrors the DFS in
/// [`convert_call_trace_into_flatcall_frame`].
fn flatcall_retained_bytes(frame: &CallFrame, depth: usize) -> usize {
    let mut total = std::mem::size_of::<LocalizedTransactionTrace>()
        .saturating_add(frame.input.len())
        .saturating_add(frame.output.as_ref().map_or(0, |output| output.len()))
        .saturating_add(frame.error.as_ref().map_or(0, String::len))
        .saturating_add(depth.saturating_mul(std::mem::size_of::<usize>()));
    for child in &frame.calls {
        total = total.saturating_add(flatcall_retained_bytes(child, depth + 1));
    }
    total
}

fn convert_call_trace_into_flatcall_frame(
    call_frame: CallFrame,
    trace_address: Vec<usize>,
    block_number: Option<u64>,
    block_hash: Option<BlockHash>,
    tx_hash: Option<TxHash>,
    tx_index: usize,
) -> Result<Vec<LocalizedTransactionTrace>, EthApiError> {
    let call_type = call_frame.typ.to_lowercase();
    let call_type = call_type.as_str();
    let trace = match call_type {
        "create" | "create2" => TransactionTrace {
            action: Action::Create(CreateAction {
                from: call_frame.from,
                gas: call_frame.gas.saturating_to(),
                init: call_frame.input,
                value: call_frame.value.unwrap_or_default(),
                creation_method: match call_type {
                    "create" => CreationMethod::Create,
                    "create2" => CreationMethod::Create2,
                    &_ => {
                        return Err(EthApiError::Unsupported("Unsupported call type"));
                    }
                },
            }),
            error: call_frame.error,
            result: Some(TraceOutput::Create(CreateOutput {
                address: call_frame.to.unwrap_or_default(),
                code: call_frame.output.unwrap_or_default(),
                gas_used: call_frame.gas_used.saturating_to(),
            })),
            subtraces: call_frame.calls.len(),
            trace_address: trace_address.clone(),
        },
        "selfdestruct" => TransactionTrace {
            action: Action::Selfdestruct(SelfdestructAction {
                address: call_frame.from,
                balance: call_frame.value.unwrap_or_default(),
                refund_address: call_frame.to.unwrap_or_default(),
            }),
            error: call_frame.error,
            result: Some(TraceOutput::Create(CreateOutput {
                address: call_frame.to.unwrap_or_default(),
                code: call_frame.output.unwrap_or_default(),
                gas_used: call_frame.gas_used.saturating_to(),
            })),
            subtraces: call_frame.calls.len(),
            trace_address: trace_address.clone(),
        },
        "call" | "staticcall" | "callcode" | "delegatecall" => TransactionTrace {
            action: Action::Call(CallAction {
                from: call_frame.from,
                call_type: match call_type {
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
                to: call_frame.to.unwrap_or_default(),
                value: call_frame.value.unwrap_or_default(),
            }),
            error: call_frame.error,
            result: Some(TraceOutput::Call(CallOutput {
                gas_used: call_frame.gas_used.saturating_to(),
                output: call_frame.output.unwrap_or_default(),
            })),
            subtraces: call_frame.calls.len(),
            trace_address: trace_address.clone(),
        },
        _ => {
            return Err(EthApiError::Unsupported("Unsupported call frame"));
        }
    };

    let frame = LocalizedTransactionTrace {
        trace,
        block_hash,
        block_number,
        transaction_hash: tx_hash,
        transaction_position: Some(tx_index as u64),
    };

    let mut result = vec![frame];
    // Consume the children by value and move their flattened frames up with `append`. Cloning each
    // child (`child_call.clone()` clones the whole subtree) and then re-cloning the returned frames
    // (`extend_from_slice`) made this O(depth^2) in deep clones: a ~1024-deep call tree produced
    // hundreds of thousands of frame copies, none of them budgeted, after the last memory check.
    // ponytail: frames are still moved once per level up to the root (O(n^2) shallow memcpy, no
    // allocation); thread a `&mut Vec` accumulator down if that CPU cost ever shows up in a profile.
    for (i, child_call) in call_frame.calls.into_iter().enumerate() {
        let mut new_trace_address = Vec::with_capacity(trace_address.len() + 1);
        new_trace_address.extend_from_slice(&trace_address);
        new_trace_address.push(i);

        let mut frames = convert_call_trace_into_flatcall_frame(
            child_call,
            new_trace_address,
            block_number,
            block_hash,
            tx_hash,
            tx_index,
        )?;
        result.append(&mut frames);
    }

    Ok(result)
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
    // value is the occurrence of the key
    for call_frame in call_frames {
        let input = call_frame.input;
        // If this is a function call (function selector is 4 bytes long)
        if input.len() >= 4 {
            let input_size = input.0.len() - 4;
            // Encode only the selector; `input.to_string()` would hex the entire calldata just to
            // read its first four bytes.
            let four_byte = alloy_primitives::hex::encode(&input[..4]);
            let key = format!("{four_byte}-{input_size}");
            let count = four_byte_map.entry(key).or_insert(0);
            *count += 1;
        }
        four_byte_map = convert_call_trace_into_4byte_map(call_frame.calls, four_byte_map);
    }
    four_byte_map
}

fn create_trace_cache_opts() -> GethDebugTracingOptions {
    // Get the traces with call tracer onlytopcall None (false) and withlog true and always cache this way
    GethDebugTracingOptions::call_tracer(CallConfig::default().with_log())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, Bytes, B256};

    use super::*;

    fn call(typ: &str, input: &[u8], calls: Vec<CallFrame>) -> CallFrame {
        CallFrame {
            typ: typ.to_string(),
            from: Address::ZERO,
            input: Bytes::copy_from_slice(input),
            calls,
            ..Default::default()
        }
    }

    /// The flatcall conversion must emit one frame per call node in depth-first pre-order, with the
    /// trace address and subtrace count of each node preserved. Pins the ownership-consuming
    /// traversal that replaced the earlier clone-per-level (O(depth^2)) converter.
    #[test]
    fn flatcall_frame_is_preorder_and_complete() {
        // root -> [child0 -> [grandchild], child1]
        let tree = call(
            "CALL",
            &[],
            vec![
                call("STATICCALL", &[], vec![call("CALL", &[], vec![])]),
                call("DELEGATECALL", &[], vec![]),
            ],
        );

        let frames = convert_call_trace_into_flatcall_frame(
            tree,
            vec![],
            Some(1),
            Some(B256::ZERO),
            Some(B256::ZERO),
            0,
        )
        .expect("a well-formed call tree converts");

        let addrs: Vec<&Vec<usize>> = frames.iter().map(|f| &f.trace.trace_address).collect();
        assert_eq!(
            addrs,
            vec![&vec![], &vec![0], &vec![0, 0], &vec![1]],
            "frames must be depth-first pre-order with correct trace addresses"
        );
        let subtraces: Vec<usize> = frames.iter().map(|f| f.trace.subtraces).collect();
        assert_eq!(
            subtraces,
            vec![2, 1, 0, 0],
            "subtrace counts must match the tree"
        );
    }

    /// The flatcall size preflight must count exactly what the conversion retains (each frame's
    /// struct, input, output, error and `traceAddress`), so it neither under-charges the response
    /// nor over-rejects a legitimate trace.
    #[test]
    fn flatcall_retained_bytes_matches_conversion() {
        // root -> [child0 -> [grandchild], child1]; addresses [], [0], [0,0], [1]
        let mut tree = call(
            "CALL",
            &[1, 2, 3, 4],
            vec![
                call("STATICCALL", &[5; 36], vec![call("CALL", &[], vec![])]),
                call("DELEGATECALL", &[], vec![]),
            ],
        );
        tree.output = Some(Bytes::from_static(&[6; 64]));
        tree.calls[1].error = Some("execution reverted".to_string());

        let frames = convert_call_trace_into_flatcall_frame(
            tree.clone(),
            vec![],
            Some(1),
            Some(B256::ZERO),
            Some(B256::ZERO),
            0,
        )
        .expect("a well-formed call tree converts");
        let retained: usize = frames
            .iter()
            .map(|f| {
                let (Action::Call(action), Some(TraceOutput::Call(output))) =
                    (&f.trace.action, &f.trace.result)
                else {
                    unreachable!("the tree only holds calls")
                };
                std::mem::size_of::<LocalizedTransactionTrace>()
                    + action.input.len()
                    + output.output.len()
                    + f.trace.error.as_ref().map_or(0, String::len)
                    + f.trace.trace_address.len() * std::mem::size_of::<usize>()
            })
            .sum();
        assert_eq!(flatcall_retained_bytes(&tree, 0), retained);
    }

    /// The four byte map keys each call by its selector and calldata size. The selector is the hex
    /// of the first four input bytes only, and calls with fewer than four bytes are ignored. Pins
    /// the `hex::encode(input[..4])` that replaced hex-encoding the whole calldata.
    #[test]
    fn four_byte_map_uses_selector_only() {
        let frames = vec![
            // selector deadbeef, 4 extra calldata bytes -> "deadbeef-4"
            call(
                "CALL",
                &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03],
                // same selector, no extra bytes -> "deadbeef-0"
                vec![call("CALL", &[0xde, 0xad, 0xbe, 0xef], vec![])],
            ),
            // fewer than four bytes -> no key
            call("CALL", &[0x01, 0x02, 0x03], vec![]),
        ];

        let FourByteFrame(map) = convert_call_trace_into_4byte_frame(frames);

        assert_eq!(map.get("deadbeef-4"), Some(&1));
        assert_eq!(map.get("deadbeef-0"), Some(&1));
        assert_eq!(map.len(), 2, "sub-4-byte calldata must not produce a key");
    }
}
