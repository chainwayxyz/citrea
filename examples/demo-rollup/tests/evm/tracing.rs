use citrea_stf::genesis_config::GenesisPaths;
use reth_rpc_types::trace::geth::{
    CallFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
    GethTrace::{self, CallTracer},
};
// use sov_demo_rollup::initialize_logging;
use ethers::abi::Address;
use serde_json::{self, json};
use sov_evm::{CallerContract, SimpleStorageContract};
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_stf_runner::RollupProverConfig;
use std::str::FromStr;

use crate::evm::make_test_client;
use crate::test_helpers::{start_rollup, NodeMode};

#[tokio::test]
async fn tracing_tests() -> Result<(), Box<dyn std::error::Error>> {
    let (port_tx, port_rx) = tokio::sync::oneshot::channel();
    let rollup_task = tokio::spawn(async {
        // Don't provide a prover since the EVM is not currently provable
        start_rollup(
            port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Skip,
            NodeMode::SequencerNode,
            None,
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
            .await?
            .unwrap()
            .contract_address
            .unwrap();

        let caller_contract_address = deploy_caller_contract_req
            .await?
            .unwrap()
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
        call_set_value_req.await.unwrap().unwrap().transaction_hash
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
        "gas": "0xdbba0",
        "gasUsed": "0xba65",
        "to": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
        "input": "0xb7d5b6580000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa30000000000000000000000000000000000000000000000000000000000000003",
        "calls": [
            {
                "from": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
                "gas": "0xd23f4",
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

    assert_eq!(json_res, CallTracer(reth_json));

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

    let call_tx_hash = call_get_value_req.await.unwrap().unwrap().transaction_hash;
    let send_eth_tx_hash = send_eth_req.await.unwrap().unwrap().transaction_hash;

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
        json![{"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","gas":"0xdbba0","gasUsed":"0x5208",
                "to":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92255","input":"0x","value":"0x4563918244f40000","type":"CALL"}],
    ).unwrap();
    assert_eq!(send_eth_trace, CallTracer(expected_send_eth_trace));
    let call_get_trace = test_client
        .debug_trace_transaction(
            call_tx_hash,
            Some(GethDebugTracingOptions::default().with_tracer(
                GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
            )),
        )
        .await;

    let expected_call_get_trace = serde_json::from_value::<CallFrame>(
        json![{"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","gas":"0xdbba0","gasUsed":"0x6b64","to":"0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
                "input":"0x35c152bd0000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa3",
                "output":"0x0000000000000000000000000000000000000000000000000000000000000000",
                "calls":[{"from":"0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
                            "gas":"0xd2662","gasUsed":"0x996","to":"0x5fbdb2315678afecb367f032d93f642f64180aa3",
                            "input":"0x6d4ce63c","output":"0x0000000000000000000000000000000000000000000000000000000000000003","type":"STATICCALL"}],
                "value":"0x0","type":"CALL"}],
    ).unwrap();
    assert_eq!(call_get_trace, CallTracer(expected_call_get_trace));
    rollup_task.abort();
    Ok(())
}
