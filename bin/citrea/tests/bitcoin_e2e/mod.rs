use std::path::PathBuf;

pub mod bitcoin_test;
// pub mod mempool_accept;
pub mod prover_test;
pub mod sequencer_commitments;
pub mod sequencer_test;
pub mod tx_chain;

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
