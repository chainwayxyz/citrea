use std::collections::HashMap;
use std::marker::PhantomData;

use hex::ToHex;
use proptest::prelude::any_with;
use proptest::strategy::Strategy;
use proptest::{prop_compose, proptest};
use reqwest::header::CONTENT_TYPE;
use serde_json::json;
use sha2::Digest;
use sov_db::ledger_db::{LedgerDB, SlotCommit};
use sov_mock_da::MockDaSpec;
#[cfg(test)]
use sov_mock_da::{MockBlock, MockBlockHeader, MockHash};
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::Time;
use sov_rollup_interface::rpc::HexTx;
use sov_rollup_interface::services::da::SlotData;
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

// These tests reproduce the README workflow for the ledger_rpc, ie:
// - It creates and populate a simple ledger with a few transactions
// - It initializes the rpc server
// - It successively calls the different rpc methods registered and tests the answer
#[test]
fn test_get_head() {
    let payload = jsonrpc_req!("ledger_getHead", []);
    let expected = jsonrpc_result!({"number":1,"hash":"0xd1231a38586e68d0405dc55ae6775e219f29fff1f7e0c6410d0ac069201e550b","batchRange":{"start":1,"end":3}});

    regular_test_helper(payload, &expected);
}

#[test]
fn test_get_transactions_offset_first_batch() {
    // Tests for different types of argument
    let payload = jsonrpc_req!("ledger_getTransactions", [[{"batchId": 1, "offset": 0}]]);
    let expected = jsonrpc_result!([{"hash":"0x709b55bd3da0f5a838125bd0ee20c5bfdd7caba173912d4281cae816b79a201b","eventRange":{"start":1,"end":1},"body":"74783120626f6479"}]);
    regular_test_helper(payload, &expected);

    // Tests for flattened args
    let payload = jsonrpc_req!("ledger_getTransactions", [1]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getTransactions", [[1]]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getTransactions", [[1], "standard"]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getTransactions", [[1], "compact"]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getTransactions", [[1], "full"]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getTransactions", [[{ "batchId": 1, "offset": 1}]]);
    let expected = jsonrpc_result!([{"hash":"0x27ca64c092a959c7edc525ed45e845b1de6a7590d173fd2fad9133c8a779a1e3","eventRange":{"start":1,"end":3},"body":"74783220626f6479"}]);
    regular_test_helper(payload, &expected);
}

#[test]
fn test_get_batches() {
    let payload = jsonrpc_req!("ledger_getBatches", [[2], "standard"]);
    let expected = jsonrpc_result!([{
        "hash":"0xf85fe0cb36fdaeca571c896ed476b49bb3c8eff00d935293a8967e1e9a62071e",
        "txRange":{"start":3,"end":263},
        "txs": batch2_tx_receipts().into_iter().map(|tx_receipt| hex::encode(tx_receipt.tx_hash) ).collect::<Vec<_>>(),
    }]);

    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getBatches", [[2]]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getBatches", [2]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getBatches", [[1], "compact"]);
    let expected = jsonrpc_result!([{"hash":"0xb5515a80204963f7db40e98af11aedb49a394b1c7e3d8b5b7a33346b8627444f","txRange":{"start":1,"end":3},}]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getBatches", [[1], "full"]);
    let expected = jsonrpc_result!([{"hash":"0xb5515a80204963f7db40e98af11aedb49a394b1c7e3d8b5b7a33346b8627444f","txRange":{"start":1,"end":3},"txs":[{"hash":"0x709b55bd3da0f5a838125bd0ee20c5bfdd7caba173912d4281cae816b79a201b","eventRange":{"start":1,"end":1},"body":"74783120626f6479"},{"hash":"0x27ca64c092a959c7edc525ed45e845b1de6a7590d173fd2fad9133c8a779a1e3","eventRange":{"start":1,"end":3},"body":"74783220626f6479",}],}]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getBatches", [[0], "compact"]);
    let expected = jsonrpc_result!([null]);
    regular_test_helper(payload, &expected);
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

#[test]
fn test_get_events() {
    let payload = jsonrpc_req!("ledger_getEvents", [1]);
    let expected = jsonrpc_result!([{
        "key":[101,118,101,110,116,49,95,107,101,121],
        "value":[101,118,101,110,116,49,95,118,97,108,117,101]
    }]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getEvents", [2]);
    let expected = jsonrpc_result!([{
        "key":[101,118,101,110,116,50,95,107,101,121],
        "value":[101,118,101,110,116,50,95,118,97,108,117,101]
    }]);
    regular_test_helper(payload, &expected);
    let payload = jsonrpc_req!("ledger_getEvents", [3]);
    let expected = jsonrpc_result!([{
        "key":[101,118,101,110,116,49,95,107,101,121],
        "value":[101,118,101,110,116,49,95,118,97,108,117,101]
    }]);
    regular_test_helper(payload, &expected);
    let payload = jsonrpc_req!("ledger_getEvents", [4]);
    let expected = jsonrpc_result!([{
        "key":[101,118,101,110,116,50,95,107,101,121],
        "value":[101,118,101,110,116,50,95,118,97,108,117,101]
    }]);
    regular_test_helper(payload, &expected);

    let payload = jsonrpc_req!("ledger_getEvents", [5]);
    let expected = jsonrpc_result!([null]);
    regular_test_helper(payload, &expected);
}

fn batch_receipt_without_hasher() -> impl Strategy<Value = BatchReceipt<u32, u32>> {
    let mut args = BatchReceiptStrategyArgs {
        hasher: None,
        ..Default::default()
    };
    args.transaction_strategy_args.hasher = None;
    any_with::<BatchReceipt<u32, u32>>(args)
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

fn full_tx_json(
    tx_id: usize,
    tx: &TransactionReceipt<u32>,
    tx_id_to_event_range: &HashMap<usize, (usize, usize)>,
) -> serde_json::Value {
    let (event_range_begin, event_range_end) = tx_id_to_event_range.get(&tx_id).unwrap();
    let tx_hash_hex = hex::encode(tx.tx_hash);
    match &tx.body_to_save {
        None => json!({
            "hash": format!("0x{tx_hash_hex}"),
            "eventRange": {
                "start": event_range_begin,
                "end": event_range_end
            },
        }),
        Some(body) => {
            json!({
                "hash": format!("0x{tx_hash_hex}"),
                "eventRange": {
                    "start": event_range_begin,
                    "end": event_range_end
                },
                "body": HexTx::from(body.clone()),
            })
        }
    }
}

proptest!(
    // Reduce the cases from 256 to 100 to speed up these tests
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(100))]
    #[test]
    fn proptest_get_head((slots, _, total_num_batches) in arb_slots(10, 10)){
        let last_slot = slots.last().unwrap();
        let last_slot_num_batches = last_slot.batch_receipts().len();

        let last_slot_start_batch = total_num_batches - last_slot_num_batches;
        let last_slot_end_batch = total_num_batches;

        let payload = jsonrpc_req!("ledger_getHead", ["compact"]);
        let expected = jsonrpc_result!({
            "number": slots.len(),
            "hash": format!("0x{}", hex::encode(last_slot.slot_data().hash())),
            "batchRange": {
                "start": last_slot_start_batch,
                "end": last_slot_end_batch
            }
        });
        test_helper(vec![TestExpect{ payload, expected }], slots, None);
    }


    #[test]
    fn proptest_get_batches((slots, tx_id_to_event_range, _total_num_batches) in arb_slots(10, 10), random_batch_num in 1..100){
        let mut curr_batch_num = 1;
        let mut curr_tx_num = 1;
        let random_batch_num_usize = usize::try_from(random_batch_num).unwrap();
        for slot in &slots {
            if curr_batch_num > random_batch_num_usize {
                break;
            }
            if curr_batch_num + slot.batch_receipts().len() > random_batch_num_usize {
                let curr_slot_batches = slot.batch_receipts();
                let batch_index = random_batch_num_usize - curr_batch_num;

                for i in 0..batch_index{
                    curr_tx_num += curr_slot_batches.get(i).unwrap().tx_receipts.len();
                }
                let first_tx_num = curr_tx_num;
                let curr_batch = curr_slot_batches.get(batch_index).unwrap();
                let last_tx_num = first_tx_num + curr_batch.tx_receipts.len();
                let batch_hash = hex::encode(curr_batch.hash);
                let _batch_receipt= 0;
                let tx_hashes: Vec<String> = curr_batch.tx_receipts.iter().map(|tx| {
                    hex::encode(tx.tx_hash)
                }).collect();
                let full_txs = curr_batch.tx_receipts.iter().enumerate().map(|(tx_id, tx)|
                   full_tx_json(curr_tx_num + tx_id, tx, &tx_id_to_event_range)
                ).collect::<Vec<_>>();
                test_helper(
                    vec![TestExpect{
                        payload:
                        jsonrpc_req!("ledger_getBatches", [[random_batch_num], "compact"]),
                        expected:
                        jsonrpc_result!([{"hash": format!("0x{batch_hash}"),"txRange": {"start":first_tx_num,"end":last_tx_num}}])},
                    TestExpect{
                        payload:
                        jsonrpc_req!("ledger_getBatches", [[random_batch_num], "standard"]),
                        expected:
                        jsonrpc_result!([{"hash":format!("0x{batch_hash}"),"txRange":{"start":first_tx_num,"end":last_tx_num},"txs":tx_hashes}])},
                    TestExpect{
                        payload:
                        jsonrpc_req!("ledger_getBatches", [[random_batch_num]]),
                        expected:
                        jsonrpc_result!([{"hash":format!("0x{batch_hash}"),"txRange":{"start":first_tx_num,"end":last_tx_num},"txs":tx_hashes}])},
                    TestExpect{
                        payload:
                        jsonrpc_req!("ledger_getBatches", [random_batch_num]),
                        expected:
                        jsonrpc_result!([{"hash":format!("0x{batch_hash}"),"txRange":{"start":first_tx_num,"end":last_tx_num},"txs":tx_hashes}])},
                    TestExpect{
                        payload:
                        jsonrpc_req!("ledger_getBatches", [[random_batch_num], "full"]),
                        expected:
                        jsonrpc_result!([{"hash":format!("0x{batch_hash}"),"txRange":{"start":first_tx_num,"end":last_tx_num},"txs":full_txs}])},
                    ],
                    slots, None);
                return Ok(());
            }

            curr_batch_num += slot.batch_receipts().len();
            for batch in slot.batch_receipts(){
                curr_tx_num += batch.tx_receipts.len();
            }
        }

        let payload = jsonrpc_req!("ledger_getBatches", [[random_batch_num], "compact"]);
        let expected = jsonrpc_result!([null]);
        test_helper(vec![TestExpect{payload, expected}], slots, None);
    }

    #[test]
    fn proptest_get_transactions((slots, tx_id_to_event_range, _total_num_batches) in arb_slots(10, 10), random_tx_num in 1..1000){
        let mut curr_tx_num = 1;

        let random_tx_num_usize = usize::try_from(random_tx_num).unwrap();

        for slot in &slots{
            for batch in slot.batch_receipts(){
                if curr_tx_num > random_tx_num_usize {
                    break;
                }

                if curr_tx_num + batch.tx_receipts.len() > random_tx_num_usize {
                    let tx_index = random_tx_num_usize - curr_tx_num;
                    let tx = batch.tx_receipts.get(tx_index).unwrap();

                    let tx_formatted = full_tx_json(curr_tx_num + tx_index, tx, &tx_id_to_event_range);

                    test_helper(vec![TestExpect{
                        payload:
                        jsonrpc_req!("ledger_getTransactions", [[random_tx_num]]),
                        expected:
                        jsonrpc_result!([tx_formatted])},
                        TestExpect{
                        payload:
                        jsonrpc_req!("ledger_getTransactions", [random_tx_num]),
                        expected:
                        jsonrpc_result!([tx_formatted])},
                        TestExpect{
                        payload:
                        jsonrpc_req!("ledger_getTransactions", [[random_tx_num], "compact"]),
                        expected:
                        jsonrpc_result!([tx_formatted])},
                        TestExpect{
                        payload:
                        jsonrpc_req!("ledger_getTransactions", [[random_tx_num], "standard"]),
                        expected:
                        jsonrpc_result!([tx_formatted])},
                        TestExpect{
                        payload:
                        jsonrpc_req!("ledger_getTransactions", [[random_tx_num], "full"]),
                        expected:
                        jsonrpc_result!([tx_formatted])},
                        ]
                        , slots, None);

                    return Ok(());
                }

                curr_tx_num += batch.tx_receipts.len();
            }
        }

        let payload = jsonrpc_req!("ledger_getTransactions", [[random_tx_num]]);
        let expected = jsonrpc_result!([null]);
        test_helper(vec![TestExpect{payload, expected}], slots, None);

    }

    #[test]
    fn proptest_get_events((slots, tx_id_to_event_range, _total_num_batches) in arb_slots(10, 10), random_event_num in 1..10000){
        let mut curr_tx_num = 1;

        let random_event_num_usize = usize::try_from(random_event_num).unwrap();

        for slot in &slots {
            for batch in slot.batch_receipts(){
                for tx in &batch.tx_receipts{
                    let (start_event_range, end_event_range) = tx_id_to_event_range.get(&curr_tx_num).unwrap();
                    if *start_event_range > random_event_num_usize {
                        break;
                    }

                    if random_event_num_usize < *end_event_range {
                        let event_index = random_event_num_usize - *start_event_range;
                        let event: &Event = tx.events.get(event_index).unwrap();
                        let event_json = json!({
                            "key": event.key().inner(),
                            "value": event.value().inner(),
                        });

                        test_helper(vec![TestExpect{
                            payload:
                            jsonrpc_req!("ledger_getEvents", [random_event_num_usize]),
                            expected:
                            jsonrpc_result!([event_json])}]
                            , slots, None);

                        return Ok(());
                    }
                    curr_tx_num += 1;
                }
            }
        }

        let payload = jsonrpc_req!("ledger_getEvents", [random_event_num]);
        let expected = jsonrpc_result!([null]);
        test_helper(vec![TestExpect{payload, expected}], slots, None);
    }
);
