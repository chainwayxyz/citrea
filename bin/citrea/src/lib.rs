#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use std::env;
use std::str::FromStr;

use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

mod eth;
mod rollup;
pub use rollup::*;

/// Default initialization of logging
pub fn initialize_logging(level: Level) {
    let env_filter = EnvFilter::from_str(&env::var("RUST_LOG").unwrap_or_else(|_| {
        let debug_components = vec![
            level.as_str().to_owned(),
            "jmt=info".to_owned(),
            "hyper=info".to_owned(),
            "alloy_transport_http=info".to_owned(),
            // Limit output as much as possible, use WARN.
            "risc0_zkvm=warn".to_owned(),
            "risc0_circuit_rv32im=info".to_owned(),
            "guest_execution=info".to_owned(),
            "jsonrpsee-server=info".to_owned(),
            "reqwest=info".to_owned(),
            "sov_schema_db=info".to_owned(),
            "sov_prover_storage_manager=info".to_owned(),
            // Limit output as much as possible, use WARN.
            "tokio_postgres=warn".to_owned(),
        ];
        debug_components.join(",")
    }))
    .unwrap();
    if std::env::var("JSON_LOGS").is_ok() {
        tracing_subscriber::registry()
            .with(fmt::layer().json())
            .with(env_filter)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(env_filter)
            .init();
    }

    log_panics::init();
}
