use std::net::SocketAddr;
use std::sync::Arc;

use reth_primitives::U64;
use sov_db::ledger_db::LedgerDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_ledger_rpc::server::create_rpc_module;
use sov_ledger_rpc::{HexHash, LedgerRpcClient};
use tempfile::tempdir;

async fn rpc_server() -> (jsonrpsee::server::ServerHandle, SocketAddr) {
    let dir = tempdir().unwrap();
    let db = LedgerDB::with_config(&RocksdbConfig::new(dir.path(), None, None)).unwrap();
    let rpc_module = create_rpc_module::<LedgerDB>(db);

    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    (server.start(rpc_module), addr)
}

async fn rpc_client(addr: SocketAddr) -> Arc<impl LedgerRpcClient> {
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

    rpc_client
        .get_soft_confirmation_by_number(U64::from(0))
        .await
        .unwrap();

    rpc_client
        .get_sequencer_commitments_on_slot_by_number(U64::from(0))
        .await
        .unwrap();

    rpc_client
        .get_sequencer_commitments_on_slot_by_hash(hash)
        .await
        .unwrap();

    rpc_client
        .get_batch_proofs_by_slot_height(U64::from(0))
        .await
        .unwrap();

    rpc_client
        .get_batch_proofs_by_slot_hash(hash)
        .await
        .unwrap();

    rpc_client
        .get_head_soft_confirmation_height()
        .await
        .unwrap();

    rpc_client.get_head_soft_confirmation().await.unwrap();

    rpc_client
        .get_verified_batch_proofs_by_slot_height(U64::from(0))
        .await
        .unwrap();

    rpc_client.get_last_verified_batch_proof().await.unwrap();
}
