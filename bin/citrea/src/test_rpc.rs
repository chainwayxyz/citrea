use citrea_common::utils::compute_tx_merkle_root;
#[cfg(test)]
use citrea_common::RpcConfig;
use hex::ToHex;
use reqwest::header::CONTENT_TYPE;
use sha2::Digest;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::types::soft_confirmation::StoredTransaction;
use sov_modules_api::L2Block;
use sov_rollup_interface::soft_confirmation::{L2Header, SignedL2Header};

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

fn populate_ledger(ledger_db: &mut LedgerDB, l2_blocks: Vec<L2Block<'_, [u8; 32]>>) {
    for block in l2_blocks {
        let tx_hashes = block.txs.to_vec();
        let tx_bodies = block
            .txs
            .iter()
            .map(|tx| borsh::to_vec(tx).expect("Tx serialization shouldn't fail"))
            .collect();
        ledger_db
            .commit_l2_block(block.clone(), tx_hashes, Some(tx_bodies))
            .unwrap();
    }
}

fn test_helper(test_queries: Vec<TestExpect>, l2_blocks: Vec<L2Block<'_, [u8; 32]>>) {
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
        populate_ledger(&mut ledger_db, l2_blocks);
        let server = jsonrpsee::server::ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let server_rpc_module = sov_ledger_rpc::server::create_rpc_module::<LedgerDB>(ledger_db);
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
            api_key: None,
        };

        queries_test_runner(test_queries, rpc_config).await;
    });
}

fn batch2_tx_receipts() -> (Vec<StoredTransaction>, Vec<Vec<u8>>) {
    let receipts = (0..260u64)
        .map(|i| StoredTransaction {
            hash: sha2::Sha256::digest(i.to_string()).into(),
            body: Some(b"tx body".to_vec()),
        })
        .collect();
    let bodies = (0..260u64).map(|_| b"tx body".to_vec()).collect();
    (receipts, bodies)
}

fn regular_test_helper(payload: serde_json::Value, expected: &serde_json::Value) {
    let (batch_2_receipts, _) = batch2_tx_receipts();

    let tx_hashes_1 = vec![
        ::sha2::Sha256::digest(b"tx1").into(),
        ::sha2::Sha256::digest(b"tx2").into(),
    ];

    let header1 = L2Header::new(
        1,
        0,
        [0u8; 32],
        [1u8; 32],
        ::sha2::Sha256::digest(b"prev_batch_receipt").into(),
        [1; 32],
        0,
        compute_tx_merkle_root(&tx_hashes_1).unwrap(),
        0,
    );

    let header2 = L2Header::new(
        2,
        1,
        [2; 32],
        [3; 32],
        ::sha2::Sha256::digest(b"prev_batch_receipt2").into(),
        [1; 32],
        0,
        compute_tx_merkle_root(&batch_2_receipts.iter().map(|r| r.hash).collect::<Vec<_>>())
            .unwrap(),
        0,
    );

    let signed_header1 = SignedL2Header::new(
        header1,
        ::sha2::Sha256::digest(b"batch_receipt").into(),
        vec![],
        vec![],
    );

    let signed_header2 = SignedL2Header::new(
        header2,
        ::sha2::Sha256::digest(b"batch_receipt2").into(),
        vec![],
        vec![],
    );

    let l2_blocks = vec![
        L2Block::<[u8; 32]>::new(
            signed_header1,
            tx_hashes_1.into(),
            vec![].into(),
            vec![
                "aaaaab".as_bytes().to_vec(),
                "eeeeeeeeee".as_bytes().to_vec(),
            ],
        ),
        L2Block::<[u8; 32]>::new(
            signed_header2,
            batch_2_receipts
                .iter()
                .map(|r| r.hash)
                .collect::<Vec<_>>()
                .into(),
            batch_2_receipts
                .iter()
                .map(|r| r.body.clone().unwrap())
                .collect::<Vec<_>>()
                .into(),
            vec!["c44444".as_bytes().to_vec()],
        ),
    ];

    test_helper(
        vec![TestExpect {
            payload,
            expected: expected.clone(),
        }],
        l2_blocks,
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

    let tx_hashes = vec![
        ::sha2::Sha256::digest(b"tx1").into(),
        ::sha2::Sha256::digest(b"tx2").into(),
    ];
    let empty_tx_merkle_root = compute_tx_merkle_root(&tx_hashes).unwrap();
    let expected = jsonrpc_result!({"daSlotHeight":0,"daSlotHash":"0000000000000000000000000000000000000000000000000000000000000000","daSlotTxsCommitment":"0101010101010101010101010101010101010101010101010101010101010101","depositData": ["616161616162", "65656565656565656565"],"hash":"b5515a80204963f7db40e98af11aedb49a394b1c7e3d8b5b7a33346b8627444f","l2Height":1, "txs":["709b55bd3da0f5a838125bd0ee20c5bfdd7caba173912d4281cae816b79a201b", "27ca64c092a959c7edc525ed45e845b1de6a7590d173fd2fad9133c8a779a1e3"],"prevHash":"0209d4aa08c40ed0fcb2bb6eb276481f2ad045914c3065e13e4f1657e97638b1","stateRoot":"0101010101010101010101010101010101010101010101010101010101010101","softConfirmationSignature":"","pubKey":"", "l1FeeRate":0, "timestamp": 0, "txMerkleRoot": empty_tx_merkle_root});
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
        .0
        .into_iter()
        .map(|r| borsh::to_vec(&r.hash).unwrap().encode_hex::<String>())
        .collect::<Vec<String>>();

    let tx_hashes = batch2_tx_receipts()
        .0
        .iter()
        .map(|r| r.hash)
        .collect::<Vec<_>>();
    let tx_merkle_root = compute_tx_merkle_root(&tx_hashes).unwrap();
    let expected = jsonrpc_result!(
        {"daSlotHeight":1,"daSlotHash":"0202020202020202020202020202020202020202020202020202020202020202","daSlotTxsCommitment":"0303030303030303030303030303030303030303030303030303030303030303","depositData": ["633434343434"],"hash":"f85fe0cb36fdaeca571c896ed476b49bb3c8eff00d935293a8967e1e9a62071e","l2Height":2, "txs": txs, "prevHash":"11ec8b9896aa1f400cc1dbd1b0ab3dcc97f2025b3d309b70ec249f687a807d1d","stateRoot":"0101010101010101010101010101010101010101010101010101010101010101","softConfirmationSignature":"","pubKey":"","l1FeeRate":0, "timestamp": 0, "txMerkleRoot": tx_merkle_root}
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
        .0
        .into_iter()
        .map(|r| borsh::to_vec(&r.hash).unwrap().encode_hex::<String>())
        .collect::<Vec<String>>();

    let tx_hashes = batch2_tx_receipts()
        .0
        .iter()
        .map(|r| r.hash)
        .collect::<Vec<_>>();
    let tx_merkle_root = compute_tx_merkle_root(&tx_hashes).unwrap();
    let expected = jsonrpc_result!(
        [
            {"daSlotHeight":0,"daSlotHash":"0000000000000000000000000000000000000000000000000000000000000000","daSlotTxsCommitment":"0101010101010101010101010101010101010101010101010101010101010101","depositData": ["616161616162", "65656565656565656565"],"hash":"b5515a80204963f7db40e98af11aedb49a394b1c7e3d8b5b7a33346b8627444f","l2Height":1,"txs":["709b55bd3da0f5a838125bd0ee20c5bfdd7caba173912d4281cae816b79a201b", "27ca64c092a959c7edc525ed45e845b1de6a7590d173fd2fad9133c8a779a1e3"],"prevHash":"0209d4aa08c40ed0fcb2bb6eb276481f2ad045914c3065e13e4f1657e97638b1", "stateRoot":"0101010101010101010101010101010101010101010101010101010101010101","softConfirmationSignature":"","pubKey":"","l1FeeRate":0, "timestamp": 0, "txMerkleRoot": empty_tx_merkle_root},
            {"daSlotHeight":1,"daSlotHash":"0202020202020202020202020202020202020202020202020202020202020202","daSlotTxsCommitment":"0303030303030303030303030303030303030303030303030303030303030303","depositData": ["633434343434"],"hash":"f85fe0cb36fdaeca571c896ed476b49bb3c8eff00d935293a8967e1e9a62071e","l2Height":2,"txs": txs, "prevHash": "11ec8b9896aa1f400cc1dbd1b0ab3dcc97f2025b3d309b70ec249f687a807d1d", "stateRoot":"0101010101010101010101010101010101010101010101010101010101010101","softConfirmationSignature":"","pubKey":"","l1FeeRate":0, "timestamp": 0, "txMerkleRoot": tx_merkle_root}
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
