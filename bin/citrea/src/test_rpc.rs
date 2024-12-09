#[cfg(test)]
use citrea_common::RpcConfig;
use hex::ToHex;
use reqwest::header::CONTENT_TYPE;
use sha2::Digest;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::rocks_db_config::RocksdbConfig;
use sov_mock_da::MockDaSpec;
#[cfg(test)]
use sov_modules_api::DaSpec;
use sov_rollup_interface::stf::{SoftConfirmationReceipt, TransactionReceipt};

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
    state_root: &[u8],
    soft_confirmation_receipts: Vec<SoftConfirmationReceipt<MockDaSpec>>,
    tx_bodies: Vec<Vec<Vec<u8>>>,
) {
    for (soft_confirmation_receipt, tx_bodies) in
        soft_confirmation_receipts.into_iter().zip(tx_bodies)
    {
        ledger_db
            .commit_soft_confirmation(state_root, soft_confirmation_receipt, Some(tx_bodies))
            .unwrap();
    }
}

fn test_helper(
    test_queries: Vec<TestExpect>,
    soft_confirmation_receipts: Vec<SoftConfirmationReceipt<MockDaSpec>>,
    tx_bodies: Vec<Vec<Vec<u8>>>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    rt.block_on(async {
        // Initialize the ledger database, which stores blocks, transactions, events, etc.
        let tmpdir = tempfile::tempdir().unwrap();
        let mut ledger_db =
            LedgerDB::with_config(&RocksdbConfig::new(tmpdir.path(), None, None)).unwrap();
        populate_ledger(
            &mut ledger_db,
            &[1; 32],
            soft_confirmation_receipts,
            tx_bodies,
        );
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
            enable_subscriptions: true,
            max_subscriptions_per_connection: 100,
        };

        queries_test_runner(test_queries, rpc_config).await;
    });
}

fn batch2_tx_receipts() -> (Vec<TransactionReceipt<u32>>, Vec<Vec<u8>>) {
    let receipts = (0..260u64)
        .map(|i| TransactionReceipt::<u32> {
            tx_hash: sha2::Sha256::digest(i.to_string()).into(),
            events: vec![],
            receipt: 0,
        })
        .collect();
    let bodies = (0..260u64).map(|_| b"tx body".to_vec()).collect();
    (receipts, bodies)
}

fn regular_test_helper(payload: serde_json::Value, expected: &serde_json::Value) {
    let tx_bodies_1 = vec![b"tx1 body".to_vec(), b"tx2 body".to_vec()];
    let (batch_2_receipts, tx_bodies_2) = batch2_tx_receipts();
    let soft_confirmation_receipts = vec![
        SoftConfirmationReceipt {
            l2_height: 1,
            da_slot_height: 0,
            da_slot_hash: <MockDaSpec as DaSpec>::SlotHash::from([0u8; 32]),
            da_slot_txs_commitment: <MockDaSpec as DaSpec>::SlotHash::from([1u8; 32]),
            soft_confirmation_signature: vec![],
            hash: ::sha2::Sha256::digest(b"batch_receipt").into(),
            prev_hash: ::sha2::Sha256::digest(b"prev_batch_receipt").into(),
            tx_hashes: vec![
                ::sha2::Sha256::digest(b"tx1").into(),
                ::sha2::Sha256::digest(b"tx2").into(),
            ],
            pub_key: vec![],
            deposit_data: vec![
                "aaaaab".as_bytes().to_vec(),
                "eeeeeeeeee".as_bytes().to_vec(),
            ],
            l1_fee_rate: 0,
            timestamp: 0,
        },
        SoftConfirmationReceipt {
            l2_height: 2,
            da_slot_height: 1,
            da_slot_hash: <MockDaSpec as DaSpec>::SlotHash::from([2; 32]),
            da_slot_txs_commitment: <MockDaSpec as DaSpec>::SlotHash::from([3; 32]),
            soft_confirmation_signature: vec![],
            hash: ::sha2::Sha256::digest(b"batch_receipt2").into(),
            prev_hash: ::sha2::Sha256::digest(b"prev_batch_receipt2").into(),
            tx_hashes: batch_2_receipts.iter().map(|r| r.tx_hash).collect(),
            pub_key: vec![],
            deposit_data: vec!["c44444".as_bytes().to_vec()],
            l1_fee_rate: 0,
            timestamp: 0,
        },
    ];

    let tx_bodies = vec![tx_bodies_1, tx_bodies_2];

    test_helper(
        vec![TestExpect {
            payload,
            expected: expected.clone(),
        }],
        soft_confirmation_receipts,
        tx_bodies,
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
fn test_get_soft_confirmation() {
    // Get the first soft confirmation by number
    let payload = jsonrpc_req!("ledger_getSoftConfirmationByNumber", [1]);
    let expected = jsonrpc_result!({"daSlotHeight":0,"daSlotHash":"0000000000000000000000000000000000000000000000000000000000000000","daSlotTxsCommitment":"0101010101010101010101010101010101010101010101010101010101010101","depositData": ["616161616162", "65656565656565656565"],"hash":"b5515a80204963f7db40e98af11aedb49a394b1c7e3d8b5b7a33346b8627444f","l2Height":1, "txs":["74783120626f6479", "74783220626f6479"],"prevHash":"0209d4aa08c40ed0fcb2bb6eb276481f2ad045914c3065e13e4f1657e97638b1","stateRoot":"0101010101010101010101010101010101010101010101010101010101010101","softConfirmationSignature":"","pubKey":"", "l1FeeRate":0, "timestamp": 0});
    regular_test_helper(payload, &expected);

    // Get the first soft confirmation by hash
    let payload = jsonrpc_req!(
        "ledger_getSoftConfirmationByHash",
        ["b5515a80204963f7db40e98af11aedb49a394b1c7e3d8b5b7a33346b8627444f"]
    );
    regular_test_helper(payload, &expected);

    // Get the second soft confirmation by number
    let payload = jsonrpc_req!("ledger_getSoftConfirmationByNumber", [2]);
    let txs = batch2_tx_receipts()
        .1
        .into_iter()
        .map(|body| body.encode_hex::<String>())
        .collect::<Vec<String>>();
    let expected = jsonrpc_result!(
        {"daSlotHeight":1,"daSlotHash":"0202020202020202020202020202020202020202020202020202020202020202","daSlotTxsCommitment":"0303030303030303030303030303030303030303030303030303030303030303","depositData": ["633434343434"],"hash":"f85fe0cb36fdaeca571c896ed476b49bb3c8eff00d935293a8967e1e9a62071e","l2Height":2, "txs": txs, "prevHash":"11ec8b9896aa1f400cc1dbd1b0ab3dcc97f2025b3d309b70ec249f687a807d1d","stateRoot":"0101010101010101010101010101010101010101010101010101010101010101","softConfirmationSignature":"","pubKey":"","l1FeeRate":0, "timestamp": 0}
    );
    regular_test_helper(payload, &expected);

    //  Get the second soft confirmation by hash
    let payload = jsonrpc_req!(
        "ledger_getSoftConfirmationByHash",
        ["f85fe0cb36fdaeca571c896ed476b49bb3c8eff00d935293a8967e1e9a62071e"]
    );
    regular_test_helper(payload, &expected);

    // Get range of soft confirmations
    let payload = jsonrpc_req!("ledger_getSoftConfirmationRange", [1, 2]);

    let txs = batch2_tx_receipts()
        .1
        .into_iter()
        .map(|body| body.encode_hex::<String>())
        .collect::<Vec<String>>();
    let expected = jsonrpc_result!(
        [
            {"daSlotHeight":0,"daSlotHash":"0000000000000000000000000000000000000000000000000000000000000000","daSlotTxsCommitment":"0101010101010101010101010101010101010101010101010101010101010101","depositData": ["616161616162", "65656565656565656565"],"hash":"b5515a80204963f7db40e98af11aedb49a394b1c7e3d8b5b7a33346b8627444f","l2Height":1,"txs":["74783120626f6479", "74783220626f6479"],"prevHash":"0209d4aa08c40ed0fcb2bb6eb276481f2ad045914c3065e13e4f1657e97638b1", "stateRoot":"0101010101010101010101010101010101010101010101010101010101010101","softConfirmationSignature":"","pubKey":"","l1FeeRate":0, "timestamp": 0},
            {"daSlotHeight":1,"daSlotHash":"0202020202020202020202020202020202020202020202020202020202020202","daSlotTxsCommitment":"0303030303030303030303030303030303030303030303030303030303030303","depositData": ["633434343434"],"hash":"f85fe0cb36fdaeca571c896ed476b49bb3c8eff00d935293a8967e1e9a62071e","l2Height":2,"txs": txs, "prevHash": "11ec8b9896aa1f400cc1dbd1b0ab3dcc97f2025b3d309b70ec249f687a807d1d", "stateRoot":"0101010101010101010101010101010101010101010101010101010101010101","softConfirmationSignature":"","pubKey":"","l1FeeRate":0, "timestamp": 0}
        ]
    );
    regular_test_helper(payload, &expected);
}

#[test]
fn test_get_soft_confirmation_status() {
    let payload = jsonrpc_req!("ledger_getSoftConfirmationStatus", [1]);
    let expected = jsonrpc_result!("trusted");
    regular_test_helper(payload, &expected);
    let payload = jsonrpc_req!("ledger_getSoftConfirmationStatus", [1]);
    let expected = jsonrpc_result!("trusted");
    regular_test_helper(payload, &expected);
}
