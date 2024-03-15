use serde::Deserialize;

/// Rollup Configuration
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SequencerConfig {
    /// Min. soft confirmaitons for sequencer to commit
    pub min_soft_confirmations_per_commitment: u64,
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
        "#;

        let config_file = create_config_from(config);

        let config: SequencerConfig = from_toml_path(config_file.path()).unwrap();

        let expected = SequencerConfig {
            min_soft_confirmations_per_commitment: 123,
        };
        assert_eq!(config, expected);
    }
}
