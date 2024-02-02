use demo_stf::genesis_config::GenesisPaths;
use reth_rpc_types::trace::geth::{
    CallFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, GethTrace,
};
// use sov_demo_rollup::initialize_logging;
use serde_json::{self, json};
use sov_evm::{CallerContract, SimpleStorageContract, TestContract};
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_stf_runner::RollupProverConfig;

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

    assert_eq!(
        json_res,
        reth_rpc_types::trace::geth::GethTrace::CallTracer(reth_json)
    );

    rollup_task.abort();
    Ok(())
}
