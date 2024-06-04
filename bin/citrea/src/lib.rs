#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use std::env;
use std::str::FromStr;

mod mock_rollup;
pub use mock_rollup::*;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

mod eth;

mod bitcoin_rollup;
pub use bitcoin_rollup::*;

/// Default initialization of logging
pub fn initialize_logging(level: Level) {
    let env_filter = EnvFilter::from_str(&env::var("RUST_LOG").unwrap_or_else(|_| {
        let debug_components = vec![
            level.as_str().to_owned(),
            "jmt=info".to_owned(),
            "hyper=info".to_owned(),
            "risc0_zkvm=info".to_owned(),
            "guest_execution=debug".to_owned(),
            "jsonrpsee-server=info".to_owned(),
            "reqwest=info".to_owned(),
            "sov_prover_storage_manager=info".to_owned(),
            format!("sov_mock_da::db_connector={}", level.as_str()),
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
