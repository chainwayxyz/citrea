#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use std::env;
use std::str::FromStr;

mod mock_rollup;
pub use mock_rollup::*;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

mod eth;

mod bitcoin_rollup;
pub use bitcoin_rollup::*;

/// Default initialization of logging
pub fn initialize_logging() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_str(&env::var("RUST_LOG").unwrap_or_else(|_| {
                "debug,hyper=info,risc0_zkvm=info,guest_execution=debug".to_string()
            }))
            .unwrap(),
        )
        .init();
    log_panics::init();
}
