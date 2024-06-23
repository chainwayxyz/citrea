pub mod config;
use core::net::SocketAddr;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
pub use config::UtilityServerConfig;
use sov_db::ledger_db::LedgerDB;

async fn health_check(
    Extension(state): Extension<LedgerDB>,
) -> Result<impl IntoResponse, StatusCode> {
    let current_height = state.get_head_soft_batch_height();

    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // expect next head height to be more than current head height
    let next_height = state.get_head_soft_batch_height();
    if let (Ok(next_height), Ok(current_height)) = (next_height, current_height) {
        if next_height <= current_height {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        Ok("OK".to_string())
    } else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
}

pub async fn spawn_utility_server(
    ledger_db: LedgerDB,
    listen_addr: SocketAddr,
    channel: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) {
    let app = Router::new()
        .route("/health", get(health_check))
        .layer(Extension(ledger_db));

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(listen_addr).await;

        match listener {
            Ok(listener) => {
                let addr = listener.local_addr().unwrap();
                if let Some(channel) = channel {
                    if let Err(e) = channel.send(addr) {
                        tracing::error!("Could not send bound_address {}: {}", addr, e);
                        return;
                    }
                }
                tracing::info!("Starting Utility Server on {}", addr);
                axum::serve(listener, app).await.unwrap();
            }
            Err(e) => println!("Server shutdown with error: {:?}", e),
        }
    });
}
