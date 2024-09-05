use std::net::SocketAddr;
use std::sync::Arc;

use sov_db::ledger_db::LedgerDB;
use sov_ledger_rpc::client::RpcClient;
use sov_ledger_rpc::server::rpc_module;
use sov_ledger_rpc::HexHash;
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

async fn rpc_client(addr: SocketAddr) -> Arc<impl RpcClient> {
    Arc::new(
        jsonrpsee::ws_client::WsClientBuilder::new()
            .build(format!("ws://{}", addr))
            .await
            .unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn getters_succeed() {
    let (_server_handle, addr) = rpc_server().await;
    let rpc_client = rpc_client(addr).await;
    let hash = HexHash([0; 32]);
    rpc_client
        .get_soft_confirmation_by_hash(hash)
        .await
        .unwrap();

    rpc_client.get_soft_confirmation_by_number(0).await.unwrap();

    rpc_client
        .get_sequencer_commitments_on_slot_by_number(0)
        .await
        .unwrap();

    rpc_client
        .get_sequencer_commitments_on_slot_by_hash([0; 32])
        .await
        .unwrap();

    rpc_client.get_proofs_by_slot_height(0).await.unwrap();

    rpc_client.get_proofs_by_slot_hash([0; 32]).await.unwrap();

    rpc_client
        .get_head_soft_confirmation_height()
        .await
        .unwrap();

    rpc_client.get_head_soft_confirmation().await.unwrap();

    rpc_client
        .get_verified_proofs_by_slot_height(0)
        .await
        .unwrap();

    rpc_client.get_last_verified_proof().await.unwrap();
}
