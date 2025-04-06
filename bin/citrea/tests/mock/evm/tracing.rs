use std::str::FromStr;

use alloy_primitives::ruint::aliases::U256;
// use citrea::initialize_logging;
use alloy_primitives::{Address, Bytes};
use alloy_rpc_types::{BlockNumberOrTag, TransactionInput, TransactionRequest};
use alloy_rpc_types_trace::geth::GethTrace::{self, CallTracer, FourByteTracer};
use alloy_rpc_types_trace::geth::{
    CallConfig, CallFrame, FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType,
    GethDebugTracingCallOptions, GethDebugTracingOptions, TraceResult,
};
use citrea_common::SequencerConfig;
use citrea_evm::smart_contracts::{CallerContract, SimpleStorageContract};
use citrea_stf::genesis_config::GenesisPaths;
use serde_json::{self, json};

use crate::common::client::MAX_FEE_PER_GAS;
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, NodeMode,
};
use crate::common::{make_test_client, TEST_DATA_GENESIS_PATH};

#[tokio::test(flavor = "multi_thread")]
async fn tracing_tests() -> Result<(), Box<dyn std::error::Error>> {
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
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

    let rollup_task = tokio::spawn(async {
        // Don't provide a prover since the EVM is not currently provable
        start_rollup(
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
    });

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
        .debug_trace_call(tx_request, None, Some(opts))
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

    // call the set method from the caller contract
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
        .debug_trace_call(tx_request, None, Some(opts))
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

    let expected_send_eth_trace = serde_json::from_value::<CallFrame>(
        json![{"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","gas":"0x1","gasUsed":"0x5208",
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
        json![{"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","gas":"0x1886","gasUsed":"0x6b64","to":"0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
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

    rollup_task.abort();
    Ok(())
}
