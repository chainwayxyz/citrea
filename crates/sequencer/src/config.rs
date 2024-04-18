use serde::Deserialize;

/// Rollup Configuration
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SequencerConfig {
    /// Min. soft confirmaitons for sequencer to commit
    pub min_soft_confirmations_per_commitment: u64,
    /// Sequencer specific mempool config
    pub mempool_conf: SequencerMempoolConfig,
}

/// Mempool Config for the sequencer
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SequencerMempoolConfig {
    /// Max number of transactions in the pending sub-pool
    pub pending_tx_limit: u64,
    /// Max number of transactions in the queued sub-pool
    pub queue_tx_limit: u64,
    /// Max number of transactions in the base-fee sub-pool
    pub base_fee_limit: u64,
    /// Max number of executable transaction slots guaranteed per account
    pub max_account_slots: u64,
}

impl Default for SequencerMempoolConfig {
    fn default() -> Self {
        Self {
            pending_tx_limit: 100000,
            queue_tx_limit: 100000,
            base_fee_limit: 100000,
            max_account_slots: 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use sov_stf_runner::from_toml_path;
    use tempfile::NamedTempFile;

    use super::*;

    fn create_config_from(content: &str) -> NamedTempFile {
        let mut config_file = NamedTempFile::new().unwrap();
        config_file.write_all(content.as_bytes()).unwrap();
        config_file
    }

    #[test]
    fn test_correct_config_sequencer() {
        let config = r#"
            min_soft_confirmations_per_commitment = 123
            [mempool_conf]
            pending_tx_limit = 100000
            queue_tx_limit = 100000
            base_fee_limit = 100000
            max_account_slots = 16
        "#;

        let config_file = create_config_from(config);

        let config: SequencerConfig = from_toml_path(config_file.path()).unwrap();

        let expected = SequencerConfig {
            min_soft_confirmations_per_commitment: 123,
            mempool_conf: SequencerMempoolConfig {
                pending_tx_limit: 100000,
                queue_tx_limit: 100000,
                base_fee_limit: 100000,
                max_account_slots: 16,
            },
        };
        assert_eq!(config, expected);
    }
}
