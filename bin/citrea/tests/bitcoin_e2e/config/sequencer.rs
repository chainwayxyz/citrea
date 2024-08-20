use crate::bitcoin_e2e::config::SequencerConfig;

pub fn default_sequencer_config() -> SequencerConfig {
    SequencerConfig {
        private_key: "1212121212121212121212121212121212121212121212121212121212121212".to_string(),
        min_soft_confirmations_per_commitment: 10,
        test_mode: true,
        deposit_mempool_fetch_limit: 10,
        block_production_interval_ms: 1000,
        da_update_interval_ms: 2000,
        mempool_conf: Default::default(),
    }
}
