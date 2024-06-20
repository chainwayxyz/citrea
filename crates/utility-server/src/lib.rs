pub mod config;

use std::sync::Arc;

use axum::{
    extract::Extension,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use sov_db::ledger_db::LedgerDB;

async fn root(Extension(state): Extension<LedgerDB>) -> String {
    format!("Hello, World! Counter: {:?}", state.get_head_soft_batch())
}

pub async fn spawn_utility_server(ledger_db: LedgerDB, bind_address: String, port: u16) {
    // run our app with hyper, listening globally on port 3000
    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .layer(Extension(ledger_db));
    let listener = tokio::net::TcpListener::bind((bind_address.clone().as_str(), port))
        .await
        .unwrap();

    let addr = listener.local_addr().unwrap();
    println!("Listening on {}", addr);
    tokio::spawn(async move {
        let res = axum::serve(listener, app).await;
        match res {
            Ok(_) => println!("Utility Server started successfully"),
            Err(e) => println!("Server shutdown with error: {:?}", e),
        }
    });
}
