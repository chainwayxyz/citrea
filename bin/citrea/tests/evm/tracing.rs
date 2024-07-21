use std::str::FromStr;

// use citrea::initialize_logging;
use citrea_evm::smart_contracts::{CallerContract, SimpleStorageContract};
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{Address, BlockNumberOrTag};
use reth_rpc_types::trace::geth::GethTrace::{self, CallTracer, FourByteTracer};
use reth_rpc_types::trace::geth::{
    CallConfig, CallFrame, FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType,
    GethDebugTracingOptions,
};
use serde_json::{self, json};

use crate::evm::make_test_client;
use crate::test_helpers::{start_rollup, tempdir_with_children, NodeMode};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    TEST_DATA_GENESIS_PATH,
};

#[tokio::test(flavor = "multi_thread")]
async fn tracing_tests() -> Result<(), Box<dyn std::error::Error>> {
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();
    let da_db_dir_cloned = da_db_dir.clone();
    let rollup_task = tokio::spawn(async {
        // Don't provide a prover since the EVM is not currently provable
        start_rollup(
            port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir_cloned,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();

    let test_client = make_test_client(port).await;

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

    // call the set method from the caller contract

    let tx_hash = {
        let call_set_value_req = test_client
            .contract_transaction(
                caller_contract_address,
                caller_contract.call_set_call_data(
                    reth_primitives::Address::from_slice(ss_contract_address.as_ref()),
                    3,
                ),
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
        "gas": "0xbbe0",
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
            caller_contract.call_get_call_data(reth_primitives::Address::from_slice(
                ss_contract_address.as_ref(),
            )),
            None,
        )
        .await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92255").unwrap();

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

    let expected_send_eth_trace = serde_json::from_value::<CallFrame>(
        json![{"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","gas":"0x5209","gasUsed":"0x5208",
                "to":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92255","input":"0x","value":"0x4563918244f40000","type":"CALL"}],
    ).unwrap();
    assert_eq!(send_eth_trace, CallTracer(expected_send_eth_trace.clone()));
    let call_get_trace = test_client
        .debug_trace_transaction(
            call_tx_hash,
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            )),
        )
        .await;

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

    let expected_call_get_trace = serde_json::from_value::<CallFrame>(
        json![{"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","gas":"0x6c3e","gasUsed":"0x6b64","to":"0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
                "input":"0x35c152bd0000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa3",
                "output":"0x0000000000000000000000000000000000000000000000000000000000000000",
                "calls":[{"from":"0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
                            "gas":"0xc3e","gasUsed":"0x996","to":"0x5fbdb2315678afecb367f032d93f642f64180aa3",
                            "input":"0x6d4ce63c","output":"0x0000000000000000000000000000000000000000000000000000000000000003","type":"STATICCALL"}],
                "value":"0x0","type":"CALL"}],
    ).unwrap();
    assert_eq!(call_get_trace, CallTracer(expected_call_get_trace.clone()));

    let traces = test_client
        .debug_trace_block_by_number(
            BlockNumberOrTag::Number(3),
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            )),
        )
        .await;
    assert_eq!(traces.len(), 2);
    assert_eq!(traces[1], CallTracer(expected_send_eth_trace.clone()));
    assert_eq!(traces[0], CallTracer(expected_call_get_trace.clone()));

    let block_hash = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(3)))
        .await
        .header
        .hash
        .unwrap();

    let traces = test_client
        .debug_trace_block_by_hash(
            block_hash,
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            )),
        )
        .await;

    assert_eq!(traces.len(), 2);
    assert_eq!(traces[1], CallTracer(expected_send_eth_trace.clone()));
    assert_eq!(traces[0], CallTracer(expected_call_get_trace.clone()));

    let four_byte_traces = test_client
        .debug_trace_block_by_hash(
            block_hash,
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::FourByteTracer),
            )),
        )
        .await;

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

    // Test CallConfig onlytopcall
    let traces_top_call_only = test_client
        .debug_trace_block_by_number(
            BlockNumberOrTag::Number(3),
            Some(
                GethDebugTracingOptions::default()
                    .with_tracer(GethDebugTracerType::BuiltInTracer(
                        GethDebugBuiltInTracerType::CallTracer,
                    ))
                    .call_config(CallConfig {
                        only_top_call: Some(true),
                        with_log: Some(false),
                    }),
            ),
        )
        .await;

    let expected_top_call_only_call_get_trace = serde_json::from_value::<CallFrame>(
        json![{"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","gas":"0x6c3e","gasUsed":"0x6b64","to":"0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
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
        .await;
    assert_eq!(traces.len(), 8);
    assert_eq!(traces[5], CallTracer(reth_json));
    assert_eq!(traces[6], CallTracer(expected_call_get_trace));
    assert_eq!(traces[7], CallTracer(expected_send_eth_trace));

    rollup_task.abort();
    Ok(())
}
