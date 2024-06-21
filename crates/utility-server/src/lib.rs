pub mod config;
pub use config::UtilityServerConfig;

use core::net::SocketAddr;

use axum::{extract::Extension, routing::get, Router};
use sov_db::ledger_db::LedgerDB;

async fn health_check(Extension(state): Extension<LedgerDB>) -> String {
    let head_batch = state.get_head_soft_batch();
    println!("Head batch: {:?}", head_batch);
    format!("OK")
}

pub async fn spawn_utility_server(
    ledger_db: LedgerDB,
    listen_addr: SocketAddr,
    channel: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) {
    // run our app with hyper, listening globally on port 3000
    // build our application with a route
    let app = Router::new()
        // `GET /health` goes to `health_check`
        .route("/", get(health_check))
        .layer(Extension(ledger_db));

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(listen_addr).await;

        match listener {
            Ok(listener) => {
                let addr = listener.local_addr().unwrap();
                if let Some(channel) = channel {
                    println!("Listening on {}", addr);
                    if let Err(e) = channel.send(addr) {
                        tracing::error!("Could not send bound_address {}: {}", addr, e);
                        return;
                    }
                }
                println!("Starting Utility Server on {}", addr);
                axum::serve(listener, app).await.unwrap();
            }
            Err(e) => println!("Server shutdown with error: {:?}", e),
        }
    });
}
