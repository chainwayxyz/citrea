use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::core::client::ClientT;
use sov_db::ledger_db::LedgerDB;
use sov_ledger_rpc::client::RpcClient;
use sov_ledger_rpc::server::rpc_module;
use sov_modules_api::Event;
use sov_rollup_interface::rpc::{
    BatchResponse, EventIdentifier, SlotResponse, TxIdAndOffset, TxIdentifier, TxResponse,
};
use tempfile::tempdir;

async fn rpc_server() -> (jsonrpsee::server::ServerHandle, SocketAddr) {
    let dir = tempdir().unwrap();
    let db = LedgerDB::with_path(dir).unwrap();
    let rpc_module = rpc_module::<LedgerDB, u32, u32>(db).unwrap();

    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    (server.start(rpc_module), addr)
}

async fn rpc_client(
    addr: SocketAddr,
) -> Arc<impl RpcClient<SlotResponse<u32, u32>, BatchResponse<u32, u32>, TxResponse<u32>>> {
    Arc::new(
        jsonrpsee::ws_client::WsClientBuilder::new()
            .build(format!("ws://{}", addr))
            .await
            .unwrap(),
    )
}

/// `ledger_getEvents` supports several parameter types, because of a
/// `jsonrpsee` limitation. See:
/// - https://github.com/Sovereign-Labs/sovereign-sdk/pull/1058
/// - https://github.com/Sovereign-Labs/sovereign-sdk/issues/1037
///
/// While `jsonrpsee` macro-generated clients can only generate nested array
/// types as parameters (e.g. `"params": [[1, 2, 3]]`), we want to test that
/// non-nested array types are also supported (e.g. `"params": [1, 2, 3]` and
/// `"params": [{"txId": 1, "offset": 2}]`).
#[tokio::test(flavor = "multi_thread")]
async fn get_events_patterns() {
    let (_server_handle, addr) = rpc_server().await;
    let rpc_client = rpc_client(addr).await;

    rpc_client
        .get_events(vec![EventIdentifier::Number(2)])
        .await
        .unwrap();
    rpc_client
        .request::<Vec<Option<Event>>, _>("ledger_getEvents", vec![vec![2]])
        .await
        .unwrap();
    rpc_client
        .request::<Vec<Option<Event>>, _>("ledger_getEvents", vec![2])
        .await
        .unwrap();
    rpc_client
        .request::<Vec<Option<Event>>, _>(
            "ledger_getEvents",
            vec![EventIdentifier::TxIdAndOffset(TxIdAndOffset {
                tx_id: TxIdentifier::Number(1),
                offset: 2,
            })],
        )
        .await
        .unwrap();
}
