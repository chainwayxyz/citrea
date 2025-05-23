use std::path::PathBuf;

pub mod batch_prover_test;
pub mod light_client_test;
pub mod rollback;
mod utils;
// pub mod mempool_accept;
pub mod backup;
pub mod bitcoin_test;
pub mod fork;
#[cfg(feature = "testing")]
pub mod full_node;
pub mod guest_cycles;
pub mod sequencer_commitments;
pub mod sequencer_test;
pub mod syncing;
pub mod tangerine_related;
pub mod tx_chain;
pub mod tx_propagation;

pub(super) fn get_citrea_path() -> PathBuf {
    std::env::var("CITREA_E2E_TEST_BINARY").map_or_else(
        |_| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            manifest_dir
                .ancestors()
                .nth(2)
                .expect("Failed to find workspace root")
                .join("target")
                .join("debug")
                .join("citrea")
        },
        PathBuf::from,
    )
}

pub(super) fn get_citrea_cli_path() -> PathBuf {
    std::env::var("CITREA_CLI_E2E_TEST_BINARY").map_or_else(
        |_| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            manifest_dir
                .ancestors()
                .nth(2)
                .expect("Failed to find workspace root")
                .join("target")
                .join("debug")
                .join("citrea-cli")
        },
        PathBuf::from,
    )
}
