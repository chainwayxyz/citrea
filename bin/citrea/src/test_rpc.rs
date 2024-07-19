use std::collections::HashMap;
use std::marker::PhantomData;

use hex::ToHex;
use proptest::prelude::any_with;
use proptest::prop_compose;
use proptest::strategy::Strategy;
use reqwest::header::CONTENT_TYPE;
use sha2::Digest;
use sov_db::ledger_db::{LedgerDB, SlotCommit};
use sov_mock_da::MockDaSpec;
#[cfg(test)]
use sov_mock_da::{MockBlock, MockBlockHeader, MockHash};
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::Time;
use sov_rollup_interface::stf::fuzzing::BatchReceiptStrategyArgs;
use sov_rollup_interface::stf::{BatchReceipt, Event, SoftBatchReceipt, TransactionReceipt};
#[cfg(test)]
use sov_stf_runner::RpcConfig;

struct TestExpect {
    payload: serde_json::Value,
    expected: serde_json::Value,
}

async fn queries_test_runner(test_queries: Vec<TestExpect>, rpc_config: RpcConfig) {
    let (addr, port) = (rpc_config.bind_host, rpc_config.bind_port);
    let client = reqwest::Client::new();
    let url_str = format!("http://{addr}:{port}");

    for query in test_queries {
        let res = client
            .post(url_str.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(query.payload.to_string())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status().as_u16(), 200);

        let response_body = res.text().await.unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response_body).unwrap(),
            query.expected,
        );
    }
}

fn populate_ledger(
    ledger_db: &mut LedgerDB,
    slots: Vec<SlotCommit<MockBlock, u32, u32>>,
    soft_batch_receipts: Option<Vec<SoftBatchReceipt<u64, u32, MockDaSpec>>>,
) {
    for slot in slots {
        ledger_db.commit_slot(slot).unwrap();
    }
    if let Some(soft_batch_receipts) = soft_batch_receipts {
        for soft_batch_receipt in soft_batch_receipts {
            ledger_db
                .commit_soft_batch(soft_batch_receipt, true)
                .unwrap();
        }
    }
}

fn test_helper(
    test_queries: Vec<TestExpect>,
    slots: Vec<SlotCommit<MockBlock, u32, u32>>,
    soft_batch_receipts: Option<Vec<SoftBatchReceipt<u64, u32, MockDaSpec>>>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    rt.block_on(async {
        // Initialize the ledger database, which stores blocks, transactions, events, etc.
        let tmpdir = tempfile::tempdir().unwrap();
        let mut ledger_db = LedgerDB::with_path(tmpdir.path()).unwrap();
        populate_ledger(&mut ledger_db, slots, soft_batch_receipts);
        let server = jsonrpsee::server::ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let server_rpc_module =
            sov_ledger_rpc::server::rpc_module::<LedgerDB, u32, u32>(ledger_db).unwrap();
        let _server_handle = server.start(server_rpc_module);

        let rpc_config = RpcConfig {
            bind_host: "127.0.0.1".to_string(),
            bind_port: addr.port(),
            max_connections: 100,
            max_request_body_size: 10 * 1024 * 1024,
            max_response_body_size: 10 * 1024 * 1024,
            batch_requests_limit: 50,
        };

        queries_test_runner(test_queries, rpc_config).await;
    });
}

fn batch2_tx_receipts() -> Vec<TransactionReceipt<u32>> {
    (0..260u64)
        .map(|i| TransactionReceipt::<u32> {
            tx_hash: sha2::Sha256::digest(i.to_string()).into(),
            body_to_save: Some(b"tx body".to_vec()),
            events: vec![],
            receipt: 0,
        })
        .collect()
}

fn regular_test_helper(payload: serde_json::Value, expected: &serde_json::Value) {
    let mut slots: Vec<SlotCommit<MockBlock, u32, u32>> = vec![SlotCommit::new(MockBlock {
        header: MockBlockHeader {
            prev_hash: MockHash(sha2::Sha256::digest(b"prev_header").into()),
            hash: MockHash(sha2::Sha256::digest(b"slot_data").into()),
            txs_commitment: MockHash(sha2::Sha256::digest(b"txs_commitment").into()),
            height: 0,
            time: Time::now(),
        },
        validity_cond: Default::default(),
        blobs: Default::default(),
    })];

    let soft_batch_receipts = vec![
        SoftBatchReceipt {
            da_slot_height: 0,
            da_slot_hash: <MockDaSpec as DaSpec>::SlotHash::from([0u8; 32]),
            da_slot_txs_commitment: <MockDaSpec as DaSpec>::SlotHash::from([1u8; 32]),
            state_root: vec![],
            soft_confirmation_signature: vec![],
            hash: ::sha2::Sha256::digest(b"batch_receipt").into(),
            prev_hash: ::sha2::Sha256::digest(b"prev_batch_receipt").into(),
            tx_receipts: vec![
                TransactionReceipt::<u32> {
                    tx_hash: ::sha2::Sha256::digest(b"tx1").into(),
                    body_to_save: Some(b"tx1 body".to_vec()),
                    events: vec![],
                    receipt: 0,
                },
                TransactionReceipt::<u32> {
                    tx_hash: ::sha2::Sha256::digest(b"tx2").into(),
                    body_to_save: Some(b"tx2 body".to_vec()),
                    events: vec![
                        Event::new("event1_key", "event1_value"),
                        Event::new("event2_key", "event2_value"),
                    ],
                    receipt: 1,
                },
            ],
            phantom_data: PhantomData,
            pub_key: vec![],
            deposit_data: vec![
                "aaaaab".as_bytes().to_vec(),
                "eeeeeeeeee".as_bytes().to_vec(),
            ],
            l1_fee_rate: 0,
            timestamp: 0,
        },
        SoftBatchReceipt {
            da_slot_height: 1,
            da_slot_hash: <MockDaSpec as DaSpec>::SlotHash::from([2; 32]),
            da_slot_txs_commitment: <MockDaSpec as DaSpec>::SlotHash::from([3; 32]),
            state_root: vec![],
            soft_confirmation_signature: vec![],
            hash: ::sha2::Sha256::digest(b"batch_receipt2").into(),
            prev_hash: ::sha2::Sha256::digest(b"prev_batch_receipt2").into(),
            tx_receipts: batch2_tx_receipts(),
            phantom_data: PhantomData,
            pub_key: vec![],
            deposit_data: vec!["c44444".as_bytes().to_vec()],
            l1_fee_rate: 0,
            timestamp: 0,
        },
    ];

    let batches = vec![
        BatchReceipt {
            hash: ::sha2::Sha256::digest(b"batch_receipt").into(),
            prev_hash: ::sha2::Sha256::digest(b"prev_batch_receipt").into(),
            tx_receipts: vec![
                TransactionReceipt::<u32> {
                    tx_hash: ::sha2::Sha256::digest(b"tx1").into(),
                    body_to_save: Some(b"tx1 body".to_vec()),
                    events: vec![],
                    receipt: 0,
                },
                TransactionReceipt::<u32> {
                    tx_hash: ::sha2::Sha256::digest(b"tx2").into(),
                    body_to_save: Some(b"tx2 body".to_vec()),
                    events: vec![
                        Event::new("event1_key", "event1_value"),
                        Event::new("event2_key", "event2_value"),
                    ],
                    receipt: 1,
                },
            ],
            phantom_data: PhantomData,
        },
        BatchReceipt {
            hash: ::sha2::Sha256::digest(b"batch_receipt2").into(),
            prev_hash: ::sha2::Sha256::digest(b"prev_batch_receipt2").into(),
            tx_receipts: batch2_tx_receipts(),
            phantom_data: PhantomData,
        },
    ];

    for batch in batches {
        slots.get_mut(0).unwrap().add_batch(batch)
    }

    test_helper(
        vec![TestExpect {
            payload,
            expected: expected.clone(),
        }],
        slots,
        Some(soft_batch_receipts),
    )
}

/// Concisely generate a [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
/// request [`String`]. You must provide the method name and the parameters of
/// the request, using [`serde_json::json!`] syntax.
///
/// ```
/// let req: String = jsonrpc_req!("method", ["param1", "param2"]);
/// ```
macro_rules! jsonrpc_req {
    ($method:expr, $params:tt) => {
        ::serde_json::json!({
            "jsonrpc": "2.0",
            "method": $method,
            "params": $params,
            "id": 1
        })
    };
}

/// A counterpart to [`jsonrpc_req!`] which generates successful responses.
macro_rules! jsonrpc_result {
    ($result:tt) => {{
        ::serde_json::json!({
            "jsonrpc": "2.0",
            "result": $result,
            "id": 1
        })
    }};
}

#[test]
fn test_get_soft_batch() {
    // Get the first soft batch by number
    let payload = jsonrpc_req!("ledger_getSoftBatchByNumber", [1]);
    let expected = jsonrpc_result!({"daSlotHeight":0,"daSlotHash":"0000000000000000000000000000000000000000000000000000000000000000","daSlotTxsCommitment":"0101010101010101010101010101010101010101010101010101010101010101","depositData": ["616161616162", "65656565656565656565"],"hash":"b5515a80204963f7db40e98af11aedb49a394b1c7e3d8b5b7a33346b8627444f","l2Height":1, "txs":["74783120626f6479", "74783220626f6479"],"prevHash":"0209d4aa08c40ed0fcb2bb6eb276481f2ad045914c3065e13e4f1657e97638b1","stateRoot":"","softConfirmationSignature":"","pubKey":"", "l1FeeRate":0, "timestamp": 0});
    regular_test_helper(payload, &expected);

    // Get the first soft batch by hash
    let payload = jsonrpc_req!(
        "ledger_getSoftBatchByHash",
        ["b5515a80204963f7db40e98af11aedb49a394b1c7e3d8b5b7a33346b8627444f"]
    );
    regular_test_helper(payload, &expected);

    // Get the second soft batch by number
    let payload = jsonrpc_req!("ledger_getSoftBatchByNumber", [2]);
    let txs = batch2_tx_receipts()
        .into_iter()
        .map(|tx_receipt| tx_receipt.body_to_save.unwrap().encode_hex::<String>())
        .collect::<Vec<String>>();
    let expected = jsonrpc_result!(
        {"daSlotHeight":1,"daSlotHash":"0202020202020202020202020202020202020202020202020202020202020202","daSlotTxsCommitment":"0303030303030303030303030303030303030303030303030303030303030303","depositData": ["633434343434"],"hash":"f85fe0cb36fdaeca571c896ed476b49bb3c8eff00d935293a8967e1e9a62071e","l2Height":2, "txs": txs, "prevHash":"11ec8b9896aa1f400cc1dbd1b0ab3dcc97f2025b3d309b70ec249f687a807d1d","stateRoot":"","softConfirmationSignature":"","pubKey":"","l1FeeRate":0, "timestamp": 0}
    );
    regular_test_helper(payload, &expected);

    //  Get the second soft batch by hash
    let payload = jsonrpc_req!(
        "ledger_getSoftBatchByHash",
        ["f85fe0cb36fdaeca571c896ed476b49bb3c8eff00d935293a8967e1e9a62071e"]
    );
    regular_test_helper(payload, &expected);

    // Get range of soft batches
    let payload = jsonrpc_req!("ledger_getSoftBatchRange", [1, 2]);

    let txs = batch2_tx_receipts()
        .into_iter()
        .map(|tx_receipt| tx_receipt.body_to_save.unwrap().encode_hex::<String>())
        .collect::<Vec<String>>();
    let expected = jsonrpc_result!(
        [
            {"daSlotHeight":0,"daSlotHash":"0000000000000000000000000000000000000000000000000000000000000000","daSlotTxsCommitment":"0101010101010101010101010101010101010101010101010101010101010101","depositData": ["616161616162", "65656565656565656565"],"hash":"b5515a80204963f7db40e98af11aedb49a394b1c7e3d8b5b7a33346b8627444f","l2Height":1,"txs":["74783120626f6479", "74783220626f6479"],"prevHash":"0209d4aa08c40ed0fcb2bb6eb276481f2ad045914c3065e13e4f1657e97638b1", "stateRoot":"","softConfirmationSignature":"","pubKey":"","l1FeeRate":0, "timestamp": 0},
            {"daSlotHeight":1,"daSlotHash":"0202020202020202020202020202020202020202020202020202020202020202","daSlotTxsCommitment":"0303030303030303030303030303030303030303030303030303030303030303","depositData": ["633434343434"],"hash":"f85fe0cb36fdaeca571c896ed476b49bb3c8eff00d935293a8967e1e9a62071e","l2Height":2,"txs": txs, "prevHash": "11ec8b9896aa1f400cc1dbd1b0ab3dcc97f2025b3d309b70ec249f687a807d1d", "stateRoot":"","softConfirmationSignature":"","pubKey":"","l1FeeRate":0, "timestamp": 0}
        ]
    );
    regular_test_helper(payload, &expected);
}

#[test]
fn test_get_soft_batch_status() {
    let payload = jsonrpc_req!("ledger_getSoftConfirmationStatus", [1]);
    let expected = jsonrpc_result!("trusted");
    regular_test_helper(payload, &expected);
    let payload = jsonrpc_req!("ledger_getSoftConfirmationStatus", [1]);
    let expected = jsonrpc_result!("trusted");
    regular_test_helper(payload, &expected);
}

prop_compose! {
    fn arb_batches_and_slot_hash(max_batches : usize)
     (slot_hash in proptest::array::uniform32(0_u8..), batches in proptest::collection::vec(batch_receipt_without_hasher(), 1..max_batches)) ->
       (Vec<BatchReceipt<u32, u32>>, [u8;32]) {
        (batches, slot_hash)
    }
}

prop_compose! {
    fn arb_slots(max_slots: usize, max_batches: usize)
    (batches_and_hashes in proptest::collection::vec(arb_batches_and_slot_hash(max_batches), 1..max_slots)) -> (Vec<SlotCommit<MockBlock, u32, u32>>, HashMap<usize, (usize, usize)>, usize)
    {
        let mut slots = std::vec::Vec::with_capacity(max_slots);

        let mut total_num_batches = 1;

        let mut prev_hash = MockHash::from([0;32]);

        let mut curr_tx_id = 1;
        let mut curr_event_id = 1;

        let mut tx_id_to_event_range = HashMap::new();

        for (batches, hash) in batches_and_hashes{
            let mut new_slot = SlotCommit::new(MockBlock {
                header: MockBlockHeader {
                    hash: hash.into(),
                    txs_commitment: hash.into(),
                    prev_hash,
                    height: 0,
                    time: Time::now(),
                },
                validity_cond: Default::default(),
                blobs: Default::default()
            });

            total_num_batches += batches.len();

            for batch in batches {
                for tx in &batch.tx_receipts{
                    tx_id_to_event_range.insert(curr_tx_id, (curr_event_id, curr_event_id + tx.events.len()));

                    curr_event_id += tx.events.len();
                    curr_tx_id += 1;
                }

                new_slot.add_batch(batch);
            }


            slots.push(new_slot);

            prev_hash = MockHash::from(hash);
        }

        (slots, tx_id_to_event_range, total_num_batches)
    }
}
