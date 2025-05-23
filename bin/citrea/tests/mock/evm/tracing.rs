use std::collections::HashMap;
use std::str::FromStr;

use alloy_primitives::ruint::aliases::U256;
use alloy_primitives::{Address, Bytes};
use alloy_rpc_types::{BlockNumberOrTag, TransactionInput, TransactionRequest};
use alloy_rpc_types_trace::geth::call::FlatCallFrame;
use alloy_rpc_types_trace::geth::mux::{MuxConfig, MuxFrame};
use alloy_rpc_types_trace::geth::GethTrace::{
    self, CallTracer, FlatCallTracer, FourByteTracer, MuxTracer, PreStateTracer,
};
use alloy_rpc_types_trace::geth::{
    CallConfig, CallFrame, FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType,
    GethDebugTracingCallOptions, GethDebugTracingOptions, PreStateFrame, TraceResult,
};
// use citrea::initialize_logging;
use citrea_common::SequencerConfig;
use citrea_evm::smart_contracts::{CallerContract, SimpleStorageContract};
use citrea_stf::genesis_config::GenesisPaths;
use reth_tasks::TaskManager;
use serde_json::{self, json};

use crate::common::client::{TestClient, MAX_FEE_PER_GAS};
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, NodeMode,
};
use crate::common::{make_test_client, TEST_DATA_GENESIS_PATH};

struct TestContractInfo {
    caller_contract_address: Address,
    caller_contract: CallerContract,
    ss_contract_address: Address,
}

async fn init_sequencer(
) -> Result<(TaskManager, Box<TestClient>, TestContractInfo), Box<dyn std::error::Error>> {
    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig::default();

    // Don't provide a prover since the EVM is not currently provable
    let rollup_task = start_rollup(
        port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config),
        None,
        false,
    )
    .await;

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();

    let test_client = make_test_client(port).await?;

    // ss is short for simple storage in this context
    let (caller_contract_address, caller_contract, ss_contract_address, _ss_contract) = {
        // caller contract has methods to call simple_storage contract
        // can call get with address and set with address and value
        let ss_contract = SimpleStorageContract::default();
        let deploy_ss_contract_req = test_client
            .deploy_contract(ss_contract.byte_code(), None)
            .await?;
        let caller_contract = CallerContract::default();
        let deploy_caller_contract_req = test_client
            .deploy_contract(caller_contract.byte_code(), None)
            .await?;

        test_client.send_publish_batch_request().await;

        let ss_contract_address = deploy_ss_contract_req
            .get_receipt()
            .await?
            .contract_address
            .unwrap();

        let caller_contract_address = deploy_caller_contract_req
            .get_receipt()
            .await?
            .contract_address
            .unwrap();

        (
            caller_contract_address,
            caller_contract,
            ss_contract_address,
            ss_contract,
        )
    };

    Ok((
        rollup_task,
        test_client,
        TestContractInfo {
            caller_contract_address,
            caller_contract,
            ss_contract_address,
        },
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_call_tracer() -> Result<(), Box<dyn std::error::Error>> {
    let (task_manager, test_client, contract_info) = init_sequencer().await?;
    let TestContractInfo {
        caller_contract_address,
        caller_contract,
        ss_contract_address,
    } = contract_info;

    let tx_request = TransactionRequest {
        from: Some(test_client.from_addr),
        to: Some(alloy_primitives::TxKind::Call(caller_contract_address)),
        gas_price: None,
        max_fee_per_gas: Some(MAX_FEE_PER_GAS),
        max_priority_fee_per_gas: None,
        max_fee_per_blob_gas: None,
        gas: None,
        value: None,
        input: TransactionInput::new(
            caller_contract
                .call_set_call_data(Address::from_slice(ss_contract_address.as_ref()), 3)
                .into(),
        ),
        nonce: None,
        chain_id: None,
        access_list: None,
        transaction_type: None,
        blob_versioned_hashes: None,
        sidecar: None,
        authorization_list: None,
    };

    let opts = GethDebugTracingCallOptions::default().with_tracing_options(
        GethDebugTracingOptions::default().with_tracer(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::CallTracer,
        )),
    );

    let call_frame_call_trace = test_client
        .debug_trace_call(tx_request.clone(), None, Some(opts))
        .await;

    let json_value = serde_json::from_value::<CallFrame>(json! [{
      "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
      "gas": "0x1c96f3c",
      "gasUsed": "0xba65",
      "to": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
      "input": "0xb7d5b6580000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa30000000000000000000000000000000000000000000000000000000000000003",
      "calls": [
        {
          "from": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
          "gas": "0x1c23bb5",
          "gasUsed": "0x57f2",
          "to": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
          "input": "0x60fe47b10000000000000000000000000000000000000000000000000000000000000003",
          "calls": [],
          "logs": [],
          "value": "0",
          "type": "CALL"
        }
      ],
      "logs": [],
      "value": "0",
      "type": "CALL"
    }]).unwrap();

    // now let's check if the traces are correct
    assert!(matches!(call_frame_call_trace, GethTrace::CallTracer(_)));

    assert_eq!(call_frame_call_trace, CallTracer(json_value.clone()));

    let tx_hash = {
        let call_set_value_req = test_client
            .contract_transaction(
                caller_contract_address,
                caller_contract
                    .call_set_call_data(Address::from_slice(ss_contract_address.as_ref()), 3),
                None,
            )
            .await;
        test_client.send_publish_batch_request().await;
        call_set_value_req
            .get_receipt()
            .await
            .unwrap()
            .transaction_hash
    };

    let json_res = test_client
        .debug_trace_transaction(
            tx_hash,
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            )),
        )
        .await;

    // the gas used inside the call is actually equal to the gas used in the call in reth
    // It was replaced with the gas limit in our trace.
    let reth_json = serde_json::from_value::<CallFrame>(json![{
        "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        "gas": "0x679c",
        "gasUsed": "0xba65",
        "to": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
        "input": "0xb7d5b6580000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa30000000000000000000000000000000000000000000000000000000000000003",
        "calls": [
            {
                "from": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
                "gas": "0x5833",
                "gasUsed": "0x57f2",
                "to": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                "input": "0x60fe47b10000000000000000000000000000000000000000000000000000000000000003",
                "value": "0x0",
                "type": "CALL"
            }
        ],
        "value": "0x0",
        "type": "CALL"
    }]).unwrap();

    // now let's check if the traces are correct
    assert!(matches!(json_res, GethTrace::CallTracer(_)));

    assert_eq!(json_res, CallTracer(reth_json.clone()));

    // Create multiple txs in the same block to test the if tracing works with cache enabled
    let call_get_value_req = test_client
        .contract_transaction(
            caller_contract_address,
            caller_contract.call_get_call_data(Address::from_slice(ss_contract_address.as_ref())),
            None,
        )
        .await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92255").unwrap();

    let tx_request = TransactionRequest {
        from: Some(test_client.from_addr),
        to: Some(alloy_primitives::TxKind::Call(addr)),
        gas_price: None,
        max_fee_per_gas: Some(1_000_000_000u128),
        max_priority_fee_per_gas: None,
        max_fee_per_blob_gas: None,
        gas: None,
        value: Some(U256::from(5_000_000_000_000_000_000u128)),
        input: TransactionInput::default(),
        nonce: None,
        chain_id: None,
        access_list: None,
        transaction_type: None,
        blob_versioned_hashes: None,
        sidecar: None,
        authorization_list: None,
    };

    let opts = GethDebugTracingCallOptions::default();
    let default_frame_call_trace = test_client
        .debug_trace_call(tx_request.clone(), None, Some(opts))
        .await
        .try_into_default_frame()
        .unwrap();

    assert!(!default_frame_call_trace.failed);
    assert_eq!(default_frame_call_trace.gas, 21000);
    assert_eq!(default_frame_call_trace.return_value, Bytes::default());

    let opts = GethDebugTracingCallOptions::default().with_tracing_options(
        GethDebugTracingOptions::default().with_tracer(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::CallTracer,
        )),
    );
    let call_frame_call_trace = test_client
        .debug_trace_call(tx_request.clone(), None, Some(opts))
        .await
        .try_into_call_frame()
        .unwrap();

    assert_eq!(call_frame_call_trace.from, test_client.from_addr);
    assert_eq!(call_frame_call_trace.gas_used.to::<u64>(), 21000u64);
    assert_eq!(call_frame_call_trace.to, Some(addr));
    assert_eq!(call_frame_call_trace.input, Bytes::default());
    assert_eq!(call_frame_call_trace.output, None);
    assert_eq!(call_frame_call_trace.error, None);
    assert_eq!(call_frame_call_trace.revert_reason, None);
    assert_eq!(call_frame_call_trace.calls, vec![]);
    assert_eq!(call_frame_call_trace.logs, vec![]);
    assert_eq!(
        call_frame_call_trace.value,
        Some(U256::from(5_000_000_000_000_000_000u128))
    );

    let send_eth_req = test_client
        .send_eth(addr, None, None, None, 5_000_000_000_000_000_000u128)
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;

    let call_tx_hash = call_get_value_req
        .get_receipt()
        .await
        .unwrap()
        .transaction_hash;
    let send_eth_tx_hash = send_eth_req.get_receipt().await.unwrap().transaction_hash;

    // get the trace of send_eth_tx_hash and expect call_tx_hash trace to be in the cache
    let send_eth_trace = test_client
        .debug_trace_transaction(
            send_eth_tx_hash,
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            )),
        )
        .await;

    let expected_send_eth_trace = serde_json::from_value::<CallFrame>(json![{
        "from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        "gas":"0x1",
        "gasUsed":"0x5208",
        "to":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92255",
        "input":"0x",
        "value":"0x4563918244f40000",
        "type":"CALL"
    }])
    .unwrap();
    assert_eq!(send_eth_trace, CallTracer(expected_send_eth_trace.clone()));

    let call_get_trace = test_client
        .debug_trace_transaction(
            call_tx_hash,
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            )),
        )
        .await;

    let expected_call_get_trace = serde_json::from_value::<CallFrame>(json![{
        "from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","gas":"0x1886","gasUsed":"0x6b64","to":"0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
        "input":"0x35c152bd0000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa3",
        "output":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "calls":[{
            "from":"0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
            "gas":"0xc3e","gasUsed":"0x996","to":"0x5fbdb2315678afecb367f032d93f642f64180aa3",
            "input":"0x6d4ce63c","output":"0x0000000000000000000000000000000000000000000000000000000000000003","type":"STATICCALL"
        }],
        "value":"0x0","type":"CALL"
    }]).unwrap();
    assert_eq!(call_get_trace, CallTracer(expected_call_get_trace.clone()));

    let traces = test_client
        .debug_trace_block_by_number(
            BlockNumberOrTag::Number(3),
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            )),
        )
        .await
        .into_iter()
        .map(|trace| match trace {
            TraceResult::Success { result, .. } => Ok(result),
            _ => anyhow::bail!("Unexpected trace result"),
        })
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(traces.len(), 2);
    assert_eq!(traces[1], CallTracer(expected_send_eth_trace.clone()));
    assert_eq!(traces[0], CallTracer(expected_call_get_trace.clone()));

    let block_hash = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(3)))
        .await
        .header
        .hash;

    let traces = test_client
        .debug_trace_block_by_hash(
            block_hash,
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            )),
        )
        .await
        .into_iter()
        .map(|trace| match trace {
            TraceResult::Success { result, .. } => Ok(result),
            _ => anyhow::bail!("Unexpected trace result"),
        })
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(traces.len(), 2);
    assert_eq!(traces[1], CallTracer(expected_send_eth_trace.clone()));
    assert_eq!(traces[0], CallTracer(expected_call_get_trace.clone()));

    // Test CallConfig onlytopcall
    let traces_top_call_only = test_client
        .debug_trace_block_by_number(
            BlockNumberOrTag::Number(3),
            Some(
                GethDebugTracingOptions::default()
                    .with_tracer(GethDebugTracerType::BuiltInTracer(
                        GethDebugBuiltInTracerType::CallTracer,
                    ))
                    .with_call_config(CallConfig {
                        only_top_call: Some(true),
                        with_log: Some(false),
                    }),
            ),
        )
        .await
        .into_iter()
        .map(|trace| match trace {
            TraceResult::Success { result, .. } => Ok(result),
            _ => anyhow::bail!("Unexpected trace result"),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let expected_top_call_only_call_get_trace = serde_json::from_value::<CallFrame>(
        json![{"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","gas":"0x1886","gasUsed":"0x6b64","to":"0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
                "input":"0x35c152bd0000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa3",
                "output":"0x0000000000000000000000000000000000000000000000000000000000000000",
                "calls":[],
                "value":"0x0","type":"CALL"}],
    ).unwrap();

    assert_eq!(traces_top_call_only.len(), 2);
    assert_eq!(
        traces_top_call_only[1],
        CallTracer(expected_send_eth_trace.clone())
    );
    assert_eq!(
        traces_top_call_only[0],
        CallTracer(expected_top_call_only_call_get_trace)
    );

    let traces = test_client
        .debug_trace_chain(
            BlockNumberOrTag::Number(0),
            BlockNumberOrTag::Latest,
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            )),
        )
        .await
        .into_iter()
        .map(|trace| match trace {
            TraceResult::Success { result, .. } => Ok(result),
            _ => anyhow::bail!("Unexpected trace result"),
        })
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(traces.len(), 8);
    assert_eq!(traces[5], CallTracer(reth_json));
    assert_eq!(traces[6], CallTracer(expected_call_get_trace));
    assert_eq!(traces[7], CallTracer(expected_send_eth_trace));

    task_manager.graceful_shutdown();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_flat_call_tracer() -> Result<(), Box<dyn std::error::Error>> {
    let (task_manager, test_client, contract_info) = init_sequencer().await?;
    let TestContractInfo {
        caller_contract_address,
        caller_contract,
        ss_contract_address,
    } = contract_info;

    let tx_request = TransactionRequest {
        from: Some(test_client.from_addr),
        to: Some(alloy_primitives::TxKind::Call(caller_contract_address)),
        gas_price: None,
        max_fee_per_gas: Some(MAX_FEE_PER_GAS),
        max_priority_fee_per_gas: None,
        max_fee_per_blob_gas: None,
        gas: None,
        value: None,
        input: TransactionInput::new(
            caller_contract
                .call_set_call_data(Address::from_slice(ss_contract_address.as_ref()), 3)
                .into(),
        ),
        nonce: None,
        chain_id: None,
        access_list: None,
        transaction_type: None,
        blob_versioned_hashes: None,
        sidecar: None,
        authorization_list: None,
    };

    let opts = GethDebugTracingCallOptions::default().with_tracing_options(
        GethDebugTracingOptions::default().with_tracer(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::FlatCallTracer,
        )),
    );

    let flat_call_frame_trace = test_client
        .debug_trace_call(tx_request.clone(), None, Some(opts))
        .await;

    let json_value = serde_json::from_value::<FlatCallFrame>(json! [[{
        "action": {
            "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "callType": "call",
            "gas": "0x1c9c380",
            "input": "0xb7d5b6580000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa30000000000000000000000000000000000000000000000000000000000000003",
            "to": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
            "value": "0x0"
        },
        "result": {
            "gasUsed": "0x6621",
            "output": "0x"
        },
        "subtraces": 1,
        "traceAddress": [],
        "type": "call"
    }, {
        "action": {
            "from": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
            "callType": "call",
            "gas": "0x1c23bb5",
            "input": "0x60fe47b10000000000000000000000000000000000000000000000000000000000000003",
            "to": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
            "value": "0x0"
        },
        "result": {
            "gasUsed": "0x57f2",
            "output": "0x"
        },
        "subtraces": 0,
        "traceAddress": [0],
        "type": "call"
    }]]).unwrap();

    // now let's check if the traces are correct
    assert!(matches!(
        flat_call_frame_trace,
        GethTrace::FlatCallTracer(_)
    ));
    assert_eq!(flat_call_frame_trace, FlatCallTracer(json_value.clone()));

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92255").unwrap();

    let tx_request = TransactionRequest {
        from: Some(test_client.from_addr),
        to: Some(alloy_primitives::TxKind::Call(addr)),
        gas_price: None,
        max_fee_per_gas: Some(1_000_000_000u128),
        max_priority_fee_per_gas: None,
        max_fee_per_blob_gas: None,
        gas: None,
        value: Some(U256::from(5_000_000_000_000_000_000u128)),
        input: TransactionInput::default(),
        nonce: None,
        chain_id: None,
        access_list: None,
        transaction_type: None,
        blob_versioned_hashes: None,
        sidecar: None,
        authorization_list: None,
    };

    // call the set method from the caller contract
    let opts = GethDebugTracingCallOptions::default().with_tracing_options(
        GethDebugTracingOptions::default().with_tracer(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::FlatCallTracer,
        )),
    );
    let flat_call_frame_call_trace = test_client
        .debug_trace_call(tx_request, None, Some(opts))
        .await
        .try_into_flat_call_frame()
        .unwrap();

    let expected_result = serde_json::from_value::<FlatCallFrame>(json![[{
        "action": {
            "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "callType": "call",
            "gas": "0x1c9c380",
            "input": "0x",
            "to": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92255",
            "value": "0x4563918244f40000"
        },
        "result": {
            "gasUsed": "0x0",
            "output": "0x"
        },
        "subtraces":0,
        "traceAddress":[],
        "type": "call"
    }]])
    .unwrap();

    assert_eq!(expected_result, flat_call_frame_call_trace);

    task_manager.graceful_shutdown();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pre_state_tracer() -> Result<(), Box<dyn std::error::Error>> {
    let (task_manager, test_client, contract_info) = init_sequencer().await?;
    let TestContractInfo {
        caller_contract_address,
        caller_contract,
        ss_contract_address,
    } = contract_info;

    let tx_request = TransactionRequest {
        from: Some(test_client.from_addr),
        to: Some(alloy_primitives::TxKind::Call(caller_contract_address)),
        gas_price: None,
        max_fee_per_gas: Some(MAX_FEE_PER_GAS),
        max_priority_fee_per_gas: None,
        max_fee_per_blob_gas: None,
        gas: None,
        value: None,
        input: TransactionInput::new(
            caller_contract
                .call_set_call_data(Address::from_slice(ss_contract_address.as_ref()), 3)
                .into(),
        ),
        nonce: None,
        chain_id: None,
        access_list: None,
        transaction_type: None,
        blob_versioned_hashes: None,
        sidecar: None,
        authorization_list: None,
    };

    let opts = GethDebugTracingCallOptions::default().with_tracing_options(
        GethDebugTracingOptions::default().with_tracer(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::PreStateTracer,
        )),
    );

    let prestate_call_frame_trace = test_client
        .debug_trace_call(tx_request.clone(), None, Some(opts))
        .await;

    let json_value = serde_json::from_value::<PreStateFrame>(json! [{
        "0x3100000000000000000000000000000000000003": {
            "balance": "0x11f16a6ce7340",
            "code": "0x60806040523661001357610011610017565b005b6100115b61001f610168565b6001600160a01b0316330361015e5760606001600160e01b03195f35166364d3180d60e11b81016100595761005261019a565b9150610156565b63587086bd60e11b6001600160e01b0319821601610079576100526101ed565b63070d7c6960e41b6001600160e01b031982160161009957610052610231565b621eb96f60e61b6001600160e01b03198216016100b857610052610261565b63a39f25e560e01b6001600160e01b03198216016100d8576100526102a0565b60405162461bcd60e51b815260206004820152604260248201527f5472616e73706172656e745570677261646561626c6550726f78793a2061646d60448201527f696e2063616e6e6f742066616c6c6261636b20746f2070726f78792074617267606482015261195d60f21b608482015260a4015b60405180910390fd5b815160208301f35b6101666102b3565b565b5f7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b546001600160a01b0316919050565b60606101a46102c3565b5f6101b23660048184610668565b8101906101bf91906106aa565b90506101da8160405180602001604052805f8152505f6102cd565b505060408051602081019091525f815290565b60605f806101fe3660048184610668565b81019061020b91906106d7565b9150915061021b828260016102cd565b60405180602001604052805f8152509250505090565b606061023b6102c3565b5f6102493660048184610668565b81019061025691906106aa565b90506101da816102f8565b606061026b6102c3565b5f610274610168565b604080516001600160a01b03831660208201529192500160405160208183030381529060405291505090565b60606102aa6102c3565b5f61027461034f565b6101666102be61034f565b61035d565b3415610166575f5ffd5b6102d68361037b565b5f825111806102e25750805b156102f3576102f183836103ba565b505b505050565b7f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f610321610168565b604080516001600160a01b03928316815291841660208301520160405180910390a161034c816103e6565b50565b5f61035861048f565b905090565b365f5f375f5f365f845af43d5f5f3e808015610377573d5ff35b3d5ffd5b610384816104b6565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b905f90a250565b60606103df83836040518060600160405280602781526020016107e76027913961054a565b9392505050565b6001600160a01b03811661044b5760405162461bcd60e51b815260206004820152602660248201527f455243313936373a206e65772061646d696e20697320746865207a65726f206160448201526564647265737360d01b606482015260840161014d565b807fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b80546001600160a01b0319166001600160a01b039290921691909117905550565b5f7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61018b565b6001600160a01b0381163b6105235760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b606482015260840161014d565b807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61046e565b60605f5f856001600160a01b031685604051610566919061079b565b5f60405180830381855af49150503d805f811461059e576040519150601f19603f3d011682016040523d82523d5f602084013e6105a3565b606091505b50915091506105b4868383876105be565b9695505050505050565b6060831561062c5782515f03610625576001600160a01b0385163b6106255760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161014d565b5081610636565b610636838361063e565b949350505050565b81511561064e5781518083602001fd5b8060405162461bcd60e51b815260040161014d91906107b1565b5f5f85851115610676575f5ffd5b83861115610682575f5ffd5b5050820193919092039150565b80356001600160a01b03811681146106a5575f5ffd5b919050565b5f602082840312156106ba575f5ffd5b6103df8261068f565b634e487b7160e01b5f52604160045260245ffd5b5f5f604083850312156106e8575f5ffd5b6106f18361068f565b9150602083013567ffffffffffffffff81111561070c575f5ffd5b8301601f8101851361071c575f5ffd5b803567ffffffffffffffff811115610736576107366106c3565b604051601f8201601f19908116603f0116810167ffffffffffffffff81118282101715610765576107656106c3565b60405281815282820160200187101561077c575f5ffd5b816020840160208301375f602083830101528093505050509250929050565b5f82518060208501845e5f920191825250919050565b602081525f82518060208401528060208501604085015e5f604082850101526040601f19601f8301168401019150509291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564",
            "nonce": 1
        },
        "0x3100000000000000000000000000000000000004": {
            "balance": "0x2f8",
            "code": "0x60806040523661001357610011610017565b005b6100115b61001f610168565b6001600160a01b0316330361015e5760606001600160e01b03195f35166364d3180d60e11b81016100595761005261019a565b9150610156565b63587086bd60e11b6001600160e01b0319821601610079576100526101ed565b63070d7c6960e41b6001600160e01b031982160161009957610052610231565b621eb96f60e61b6001600160e01b03198216016100b857610052610261565b63a39f25e560e01b6001600160e01b03198216016100d8576100526102a0565b60405162461bcd60e51b815260206004820152604260248201527f5472616e73706172656e745570677261646561626c6550726f78793a2061646d60448201527f696e2063616e6e6f742066616c6c6261636b20746f2070726f78792074617267606482015261195d60f21b608482015260a4015b60405180910390fd5b815160208301f35b6101666102b3565b565b5f7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b546001600160a01b0316919050565b60606101a46102c3565b5f6101b23660048184610668565b8101906101bf91906106aa565b90506101da8160405180602001604052805f8152505f6102cd565b505060408051602081019091525f815290565b60605f806101fe3660048184610668565b81019061020b91906106d7565b9150915061021b828260016102cd565b60405180602001604052805f8152509250505090565b606061023b6102c3565b5f6102493660048184610668565b81019061025691906106aa565b90506101da816102f8565b606061026b6102c3565b5f610274610168565b604080516001600160a01b03831660208201529192500160405160208183030381529060405291505090565b60606102aa6102c3565b5f61027461034f565b6101666102be61034f565b61035d565b3415610166575f5ffd5b6102d68361037b565b5f825111806102e25750805b156102f3576102f183836103ba565b505b505050565b7f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f610321610168565b604080516001600160a01b03928316815291841660208301520160405180910390a161034c816103e6565b50565b5f61035861048f565b905090565b365f5f375f5f365f845af43d5f5f3e808015610377573d5ff35b3d5ffd5b610384816104b6565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b905f90a250565b60606103df83836040518060600160405280602781526020016107e76027913961054a565b9392505050565b6001600160a01b03811661044b5760405162461bcd60e51b815260206004820152602660248201527f455243313936373a206e65772061646d696e20697320746865207a65726f206160448201526564647265737360d01b606482015260840161014d565b807fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b80546001600160a01b0319166001600160a01b039290921691909117905550565b5f7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61018b565b6001600160a01b0381163b6105235760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b606482015260840161014d565b807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61046e565b60605f5f856001600160a01b031685604051610566919061079b565b5f60405180830381855af49150503d805f811461059e576040519150601f19603f3d011682016040523d82523d5f602084013e6105a3565b606091505b50915091506105b4868383876105be565b9695505050505050565b6060831561062c5782515f03610625576001600160a01b0385163b6106255760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161014d565b5081610636565b610636838361063e565b949350505050565b81511561064e5781518083602001fd5b8060405162461bcd60e51b815260040161014d91906107b1565b5f5f85851115610676575f5ffd5b83861115610682575f5ffd5b5050820193919092039150565b80356001600160a01b03811681146106a5575f5ffd5b919050565b5f602082840312156106ba575f5ffd5b6103df8261068f565b634e487b7160e01b5f52604160045260245ffd5b5f5f604083850312156106e8575f5ffd5b6106f18361068f565b9150602083013567ffffffffffffffff81111561070c575f5ffd5b8301601f8101851361071c575f5ffd5b803567ffffffffffffffff811115610736576107366106c3565b604051601f8201601f19908116603f0116810167ffffffffffffffff81118282101715610765576107656106c3565b60405281815282820160200187101561077c575f5ffd5b816020840160208301375f602083830101528093505050509250929050565b5f82518060208501845e5f920191825250919050565b602081525f82518060208401528060208501604085015e5f604082850101526040601f19601f8301168401019150509291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564",
            "nonce": 1
        },
        "0x3100000000000000000000000000000000000005": {
            "balance": "0x370bd6",
            "code": "0x60806040523661001357610011610017565b005b6100115b61001f610168565b6001600160a01b0316330361015e5760606001600160e01b03195f35166364d3180d60e11b81016100595761005261019a565b9150610156565b63587086bd60e11b6001600160e01b0319821601610079576100526101ed565b63070d7c6960e41b6001600160e01b031982160161009957610052610231565b621eb96f60e61b6001600160e01b03198216016100b857610052610261565b63a39f25e560e01b6001600160e01b03198216016100d8576100526102a0565b60405162461bcd60e51b815260206004820152604260248201527f5472616e73706172656e745570677261646561626c6550726f78793a2061646d60448201527f696e2063616e6e6f742066616c6c6261636b20746f2070726f78792074617267606482015261195d60f21b608482015260a4015b60405180910390fd5b815160208301f35b6101666102b3565b565b5f7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b546001600160a01b0316919050565b60606101a46102c3565b5f6101b23660048184610668565b8101906101bf91906106aa565b90506101da8160405180602001604052805f8152505f6102cd565b505060408051602081019091525f815290565b60605f806101fe3660048184610668565b81019061020b91906106d7565b9150915061021b828260016102cd565b60405180602001604052805f8152509250505090565b606061023b6102c3565b5f6102493660048184610668565b81019061025691906106aa565b90506101da816102f8565b606061026b6102c3565b5f610274610168565b604080516001600160a01b03831660208201529192500160405160208183030381529060405291505090565b60606102aa6102c3565b5f61027461034f565b6101666102be61034f565b61035d565b3415610166575f5ffd5b6102d68361037b565b5f825111806102e25750805b156102f3576102f183836103ba565b505b505050565b7f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f610321610168565b604080516001600160a01b03928316815291841660208301520160405180910390a161034c816103e6565b50565b5f61035861048f565b905090565b365f5f375f5f365f845af43d5f5f3e808015610377573d5ff35b3d5ffd5b610384816104b6565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b905f90a250565b60606103df83836040518060600160405280602781526020016107e76027913961054a565b9392505050565b6001600160a01b03811661044b5760405162461bcd60e51b815260206004820152602660248201527f455243313936373a206e65772061646d696e20697320746865207a65726f206160448201526564647265737360d01b606482015260840161014d565b807fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b80546001600160a01b0319166001600160a01b039290921691909117905550565b5f7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61018b565b6001600160a01b0381163b6105235760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b606482015260840161014d565b807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61046e565b60605f5f856001600160a01b031685604051610566919061079b565b5f60405180830381855af49150503d805f811461059e576040519150601f19603f3d011682016040523d82523d5f602084013e6105a3565b606091505b50915091506105b4868383876105be565b9695505050505050565b6060831561062c5782515f03610625576001600160a01b0385163b6106255760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161014d565b5081610636565b610636838361063e565b949350505050565b81511561064e5781518083602001fd5b8060405162461bcd60e51b815260040161014d91906107b1565b5f5f85851115610676575f5ffd5b83861115610682575f5ffd5b5050820193919092039150565b80356001600160a01b03811681146106a5575f5ffd5b919050565b5f602082840312156106ba575f5ffd5b6103df8261068f565b634e487b7160e01b5f52604160045260245ffd5b5f5f604083850312156106e8575f5ffd5b6106f18361068f565b9150602083013567ffffffffffffffff81111561070c575f5ffd5b8301601f8101851361071c575f5ffd5b803567ffffffffffffffff811115610736576107366106c3565b604051601f8201601f19908116603f0116810167ffffffffffffffff81118282101715610765576107656106c3565b60405281815282820160200187101561077c575f5ffd5b816020840160208301375f602083830101528093505050509250929050565b5f82518060208501845e5f920191825250919050565b602081525f82518060208401528060208501604085015e5f604082850101526040601f19601f8301168401019150509291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564",
            "nonce": 1
        },
        "0x5fbdb2315678afecb367f032d93f642f64180aa3": {
            "balance": "0x0",
            "code": "0x608060405234801561000f575f80fd5b506004361061003f575f3560e01c80634e70b1dc1461004357806360fe47b1146100615780636d4ce63c1461007d575b5f80fd5b61004b61009b565b60405161005891906100c9565b60405180910390f35b61007b60048036038101906100769190610110565b6100a0565b005b6100856100a9565b60405161009291906100c9565b60405180910390f35b5f5481565b805f8190555050565b5f8054905090565b5f819050919050565b6100c3816100b1565b82525050565b5f6020820190506100dc5f8301846100ba565b92915050565b5f80fd5b6100ef816100b1565b81146100f9575f80fd5b50565b5f8135905061010a816100e6565b92915050565b5f60208284031215610125576101246100e2565b5b5f610132848285016100fc565b9150509291505056fea264697066735822122011ac1b48890fc5332d67a2b84f4a617f861d0d0d10b928535aa5655c9ab1c66664736f6c63430008180033",
            "nonce": 1,
            "storage": {
            "0x0000000000000000000000000000000000000000000000000000000000000000": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
        },
        "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512": {
            "balance": "0x0",
            "code": "0x608060405234801561000f575f80fd5b506004361061003f575f3560e01c806335c152bd146100435780634e70b1dc14610073578063b7d5b65814610091575b5f80fd5b61005d600480360381019061005891906101ee565b6100ad565b60405161006a9190610231565b60405180910390f35b61007b610121565b6040516100889190610231565b60405180910390f35b6100ab60048036038101906100a69190610274565b610126565b005b5f8173ffffffffffffffffffffffffffffffffffffffff16636d4ce63c6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100f7573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061011b91906102c6565b50919050565b5f5481565b8173ffffffffffffffffffffffffffffffffffffffff166360fe47b1826040518263ffffffff1660e01b815260040161015f9190610231565b5f604051808303815f87803b158015610176575f80fd5b505af1158015610188573d5f803e3d5ffd5b505050505050565b5f80fd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6101bd82610194565b9050919050565b6101cd816101b3565b81146101d7575f80fd5b50565b5f813590506101e8816101c4565b92915050565b5f6020828403121561020357610202610190565b5b5f610210848285016101da565b91505092915050565b5f819050919050565b61022b81610219565b82525050565b5f6020820190506102445f830184610222565b92915050565b61025381610219565b811461025d575f80fd5b50565b5f8135905061026e8161024a565b92915050565b5f806040838503121561028a57610289610190565b5b5f610297858286016101da565b92505060206102a885828601610260565b9150509250929050565b5f815190506102c08161024a565b92915050565b5f602082840312156102db576102da610190565b5b5f6102e8848285016102b2565b9150509291505056fea26469706673582212202297e19f360b0c5c0209ac0b3222110769714d5571b25b74824828954c03146864736f6c63430008160033",
            "nonce": 1
        },
        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266": {
            "balance": "0xfffffffffffffffffee0e958fa7df1",
            "nonce": 2
        }
    }]).unwrap();

    // now let's check if the traces are correct
    assert!(matches!(
        prestate_call_frame_trace,
        GethTrace::PreStateTracer(_)
    ));
    assert_eq!(
        prestate_call_frame_trace,
        PreStateTracer(json_value.clone())
    );

    task_manager.graceful_shutdown();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_four_byte_tracer() -> Result<(), Box<dyn std::error::Error>> {
    let (task_manager, test_client, contract_info) = init_sequencer().await?;
    let TestContractInfo {
        caller_contract_address,
        caller_contract,
        ss_contract_address,
    } = contract_info;

    let _ = test_client
        .contract_transaction(
            caller_contract_address,
            caller_contract.call_get_call_data(Address::from_slice(ss_contract_address.as_ref())),
            None,
        )
        .await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92255").unwrap();
    let _ = test_client
        .send_eth(addr, None, None, None, 5_000_000_000_000_000_000u128)
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;

    let block_hash = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(2)))
        .await
        .header
        .hash;

    let four_byte_traces = test_client
        .debug_trace_block_by_hash(
            block_hash,
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::FourByteTracer),
            )),
        )
        .await
        .into_iter()
        .map(|trace| match trace {
            TraceResult::Success { result, .. } => Ok(result),
            _ => anyhow::bail!("Unexpected trace result"),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let expected_call_get_4byte_trace =
        serde_json::from_value::<FourByteFrame>(json![{"35c152bd-32": 1, "6d4ce63c-0": 1}])
            .unwrap();
    let expected_send_eth_4byte_trace = serde_json::from_value::<FourByteFrame>(json![{}]).unwrap();

    assert_eq!(four_byte_traces.len(), 2);
    assert_eq!(
        four_byte_traces[0],
        FourByteTracer(expected_call_get_4byte_trace)
    );
    assert_eq!(
        four_byte_traces[1],
        FourByteTracer(expected_send_eth_4byte_trace)
    );

    task_manager.graceful_shutdown();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mux_tracer() -> Result<(), Box<dyn std::error::Error>> {
    let (task_manager, test_client, contract_info) = init_sequencer().await?;
    let TestContractInfo {
        caller_contract_address,
        caller_contract,
        ss_contract_address,
    } = contract_info;

    let tx_request = TransactionRequest {
        from: Some(test_client.from_addr),
        to: Some(alloy_primitives::TxKind::Call(caller_contract_address)),
        gas_price: None,
        max_fee_per_gas: Some(MAX_FEE_PER_GAS),
        max_priority_fee_per_gas: None,
        max_fee_per_blob_gas: None,
        gas: None,
        value: None,
        input: TransactionInput::new(
            caller_contract
                .call_set_call_data(Address::from_slice(ss_contract_address.as_ref()), 3)
                .into(),
        ),
        nonce: None,
        chain_id: None,
        access_list: None,
        transaction_type: None,
        blob_versioned_hashes: None,
        sidecar: None,
        authorization_list: None,
    };

    let mut opts = GethDebugTracingCallOptions::default();
    opts.tracing_options.tracer = Some(GethDebugTracerType::BuiltInTracer(
        GethDebugBuiltInTracerType::MuxTracer,
    ));

    let call_config = CallConfig {
        only_top_call: Some(true),
        with_log: Some(true),
    };

    opts.tracing_options.tracer_config = MuxConfig(HashMap::from_iter([
        (GethDebugBuiltInTracerType::FourByteTracer, None),
        (
            GethDebugBuiltInTracerType::CallTracer,
            Some(call_config.into()),
        ),
    ]))
    .into();

    let mux_call_frame_trace = test_client
        .debug_trace_call(tx_request.clone(), None, Some(opts))
        .await;

    let json_value = serde_json::from_value::<MuxFrame>(json![{
        "4byteTracer": {
            "0x60fe47b1-32": 1,
            "0xb7d5b658-64": 1
        },
        "callTracer": {
            "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "gas": "0x1c96f3c",
            "gasUsed": "0xba65",
            "to": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
            "input": "0xb7d5b6580000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa30000000000000000000000000000000000000000000000000000000000000003",
            "value": "0x0",
            "type": "CALL"
        }
    }]).unwrap();

    // now let's check if the traces are correct
    assert!(matches!(mux_call_frame_trace, GethTrace::MuxTracer(_)));
    assert_eq!(mux_call_frame_trace, MuxTracer(json_value.clone()));

    task_manager.graceful_shutdown();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_js_tracer() -> Result<(), Box<dyn std::error::Error>> {
    let (task_manager, test_client, contract_info) = init_sequencer().await?;
    let TestContractInfo {
        caller_contract_address,
        caller_contract,
        ss_contract_address,
    } = contract_info;

    let call_get_value_req = test_client
        .contract_transaction(
            caller_contract_address,
            caller_contract.call_get_call_data(Address::from_slice(ss_contract_address.as_ref())),
            None,
        )
        .await;
    test_client.send_publish_batch_request().await;

    let call_tx_hash = call_get_value_req
        .get_receipt()
        .await
        .unwrap()
        .transaction_hash;

    // Js tracer that collects the used gas at every step
    let js_code = "{gasUsed: [], step: function(log) { this.gasUsed.push(log.getGas()); }, result: function() { return this.gasUsed; }, fault: function() {}}";
    let call_js_trace = test_client
        .debug_trace_transaction(
            // using previously submitted transaction hash
            call_tx_hash,
            Some(
                GethDebugTracingOptions::default()
                    .with_tracer(GethDebugTracerType::JsTracer(js_code.to_string())),
            ),
        )
        .await;

    let js_trace_json = call_js_trace.try_into_json_value().unwrap();
    let gas_per_step = js_trace_json
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_i64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        gas_per_step,
        [
            // final gas = 6278 = 0x1886
            6278, 6275, 6272, 6260, 6258, 6255, 6252, 6249, 6239, 6238, 6236, 6233, 6231, 6228,
            6225, 6215, 6213, 6210, 6207, 6204, 6201, 6198, 6195, 6192, 6182, 6181, 6178, 6175,
            6172, 6170, 6167, 6164, 6161, 6158, 6155, 6152, 6149, 6146, 6138, 6137, 6135, 6132,
            6129, 6126, 6123, 6120, 6117, 6114, 6104, 6103, 6101, 6098, 6095, 6092, 6089, 6086,
            6083, 6075, 6074, 6072, 6069, 6066, 6063, 6061, 6058, 6055, 6052, 6044, 6043, 6040,
            6037, 6034, 6026, 6025, 6023, 6020, 6017, 6014, 6006, 6005, 6003, 6000, 5997, 5994,
            5991, 5989, 5986, 5983, 5981, 5973, 5972, 5969, 5967, 5964, 5961, 5959, 5951, 5950,
            5947, 5944, 5941, 5931, 5930, 5928, 5920, 5919, 5916, 5913, 5911, 5909, 5901, 5900,
            5897, 5895, 5893, 5890, 5887, 5885, 5883, 5875, 5874, 5871, 5863, 5862, 5860, 5857,
            5854, 5851, 5848, 5845, 5842, 5839, 5836, 5833, 5830, 5827, 5824, 5815, 5812, 5809,
            5806, 5803, 5800, 5797, 5794, 5791, 5788, 5785, 5783, 3134, 3131, 3128, 3116, 3114,
            3111, 3108, 3105, 3095, 3094, 3092, 3089, 3087, 3084, 3081, 3071, 3069, 3066, 3063,
            3060, 3057, 3054, 3051, 3048, 3038, 3035, 3032, 3029, 3026, 3016, 3013, 3010, 3007,
            3004, 2994, 2993, 2990, 2987, 2979, 2978, 2976, 2973, 873, 870, 868, 865, 857, 856,
            853, 850, 847, 844, 841, 838, 830, 829, 827, 824, 821, 818, 815, 813, 810, 808, 805,
            802, 799, 796, 788, 787, 784, 781, 778, 770, 769, 767, 764, 761, 759, 756, 753, 751,
            743, 742, 739, 730, 728, 726, 718, 717, 714, 711, 709, 707, 699, 698, 695, 692, 689,
            686, 683, 680, 729, 726, 723, 720, 717, 707, 706, 704, 702, 700, 698, 695, 692, 690,
            687, 684, 681, 678, 675, 672, 669, 666, 663, 660, 657, 655, 652, 649, 646, 643, 640,
            637, 634, 626, 625, 623, 620, 617, 614, 611, 608, 605, 602, 592, 591, 589, 586, 583,
            580, 577, 574, 571, 563, 562, 560, 557, 554, 551, 549, 546, 543, 540, 532, 531, 528,
            525, 522, 514, 513, 511, 508, 505, 503, 500, 497, 495, 487, 486, 483, 480, 477, 467,
            466, 464, 456, 455, 452, 449, 447, 445, 437, 436, 433, 431, 429, 426, 423, 421, 419,
            411, 410, 408, 405, 402, 400, 392, 391, 388, 385, 382, 379, 376, 373, 365, 364, 362,
            359, 356, 353, 350, 348, 345, 343, 340, 337, 334, 331, 323, 322, 319, 316, 313, 305,
            304, 302, 299, 296, 294, 291, 288, 286, 278, 277, 274, 268, 266, 264, 256, 255, 252,
            249, 247, 245, 237, 236, 233, 230, 227, 224, 221, 218,
        ]
        .to_vec(),
    );

    task_manager.graceful_shutdown();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_noop_tracer() -> Result<(), Box<dyn std::error::Error>> {
    let (task_manager, test_client, contract_info) = init_sequencer().await?;
    let TestContractInfo {
        caller_contract_address,
        caller_contract,
        ss_contract_address,
    } = contract_info;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92255").unwrap();
    let _ = test_client
        .send_eth(addr, None, None, None, 5_000_000_000_000_000_000u128)
        .await
        .unwrap();

    let call_get_value_req = test_client
        .contract_transaction(
            caller_contract_address,
            caller_contract.call_get_call_data(Address::from_slice(ss_contract_address.as_ref())),
            None,
        )
        .await;
    test_client.send_publish_batch_request().await;

    let call_tx_hash = call_get_value_req
        .get_receipt()
        .await
        .unwrap()
        .transaction_hash;

    let noop_opts = Some(GethDebugTracingOptions::default().with_tracer(
        GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::NoopTracer),
    ));

    let noop_call_get_trace = test_client
        .debug_trace_transaction(call_tx_hash, noop_opts)
        .await;
    let expected_noop_call_get_trace = serde_json::from_value::<FourByteFrame>(json![{}]).unwrap();
    // the response is deserialized into fourbytes from the rpc response
    // that is why we need to compare it with the FourByteTracer
    assert_eq!(
        noop_call_get_trace,
        FourByteTracer(expected_noop_call_get_trace),
    );

    task_manager.graceful_shutdown();

    Ok(())
}
