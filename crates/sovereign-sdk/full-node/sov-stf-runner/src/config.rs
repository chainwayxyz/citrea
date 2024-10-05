use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use citrea_pruning::PruningConfig;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::ProverGuestRunConfig;

/// Runner configuration.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RunnerConfig {
    /// Sequencer client configuration.
    pub sequencer_client_url: String,
    /// Saves sequencer soft confirmations if set to true
    pub include_tx_body: bool,
    /// Only true for tests
    pub accept_public_input_as_proven: Option<bool>,
    /// Number of blocks to request during sync
    #[serde(default = "default_sync_blocks_count")]
    pub sync_blocks_count: u64,
    /// Configurations for pruning
    pub pruning_config: Option<PruningConfig>,
}

/// RPC configuration.
#[derive(Debug, Clone, PartialEq, Deserialize, Default, Serialize)]
pub struct RpcConfig {
    /// RPC host.
    pub bind_host: String,
    /// RPC port.
    pub bind_port: u16,
    /// Maximum number of concurrent requests.
    /// if not set defaults to 100.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Max request body request
    #[serde(default = "default_max_request_body_size")]
    pub max_request_body_size: u32,
    /// Max response body request
    #[serde(default = "default_max_response_body_size")]
    pub max_response_body_size: u32,
    /// Maximum number of batch requests
    #[serde(default = "default_batch_requests_limit")]
    pub batch_requests_limit: u32,
    /// Disable subscription RPCs
    #[serde(default = "default_enable_subscriptions")]
    pub enable_subscriptions: bool,
    /// Maximum number of subscription connections
    #[serde(default = "default_max_subscriptions_per_connection")]
    pub max_subscriptions_per_connection: u32,
}

#[inline]
const fn default_max_connections() -> u32 {
    100
}

#[inline]
const fn default_max_request_body_size() -> u32 {
    10 * 1024 * 1024
}

#[inline]
const fn default_max_response_body_size() -> u32 {
    10 * 1024 * 1024
}

#[inline]
const fn default_batch_requests_limit() -> u32 {
    50
}

#[inline]
const fn default_sync_blocks_count() -> u64 {
    10
}

#[inline]
const fn default_enable_subscriptions() -> bool {
    true
}

#[inline]
const fn default_max_subscriptions_per_connection() -> u32 {
    100
}

/// Simple storage configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct StorageConfig {
    /// Path that can be utilized by concrete rollup implementation
    pub path: PathBuf,
    /// File descriptor limit for RocksDB
    pub db_max_open_files: Option<i32>,
}

/// Important public keys for the rollup
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RollupPublicKeys {
    /// Soft confirmation signing public key of the Sequencer
    #[serde(with = "hex::serde")]
    pub sequencer_public_key: Vec<u8>,
    /// DA Signing Public Key of the Sequencer
    /// serialized as hex
    #[serde(with = "hex::serde")]
    pub sequencer_da_pub_key: Vec<u8>,
    /// DA Signing Public Key of the Prover
    /// serialized as hex
    #[serde(with = "hex::serde")]
    pub prover_da_pub_key: Vec<u8>,
}

/// Rollup Configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct FullNodeConfig<BitcoinServiceConfig> {
    /// RPC configuration
    pub rpc: RpcConfig,
    /// Currently rollup config runner only supports storage path parameter
    pub storage: StorageConfig,
    /// Runner own configuration.
    pub runner: Option<RunnerConfig>, // optional bc sequencer doesn't need it
    /// Data Availability service configuration.
    pub da: BitcoinServiceConfig,
    /// Important pubkeys
    pub public_keys: RollupPublicKeys,
}

/// Prover configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BatchProverConfig {
    /// Prover run mode
    pub proving_mode: ProverGuestRunConfig,
    /// Average number of commitments to prove
    pub proof_sampling_number: usize,
    /// If true prover will try to recover ongoing proving sessions
    pub enable_recovery: bool,
}

impl Default for BatchProverConfig {
    fn default() -> Self {
        Self {
            proving_mode: ProverGuestRunConfig::Execute,
            proof_sampling_number: 0,
            enable_recovery: true,
        }
    }
}

/// Reads toml file as a specific type.
pub fn from_toml_path<P: AsRef<Path>, R: DeserializeOwned>(path: P) -> anyhow::Result<R> {
    let mut contents = String::new();
    {
        let mut file = File::open(path)?;
        file.read_to_string(&mut contents)?;
    }
    tracing::debug!("Config file size: {} bytes", contents.len());
    tracing::trace!("Config file contents: {}", &contents);

    let result: R = toml::from_str(&contents)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    fn create_config_from(content: &str) -> NamedTempFile {
        let mut config_file = NamedTempFile::new().unwrap();
        config_file.write_all(content.as_bytes()).unwrap();
        config_file
    }

    #[test]
    fn test_correct_rollup_config() {
        let config =
            r#"
            [public_keys]
            sequencer_public_key = "0000000000000000000000000000000000000000000000000000000000000000"
            sequencer_da_pub_key = "7777777777777777777777777777777777777777777777777777777777777777"
            prover_da_pub_key = ""
            
            [rpc]
            bind_host = "127.0.0.1"
            bind_port = 12345
            max_connections = 500
            enable_subscriptions = true
            max_subscriptions_per_connection = 200

            [da]
            sender_address = "0000000000000000000000000000000000000000000000000000000000000000"
            db_path = "/tmp/da"
            
            [storage]
            path = "/tmp/rollup"
            db_max_open_files = 123
            
            [runner]
            include_tx_body = true
            sequencer_client_url = "http://0.0.0.0:12346"
        "#.to_owned();

        let config_file = create_config_from(&config);

        let config: FullNodeConfig<sov_mock_da::MockDaConfig> =
            from_toml_path(config_file.path()).unwrap();

        let expected = FullNodeConfig {
            runner: Some(RunnerConfig {
                sequencer_client_url: "http://0.0.0.0:12346".to_owned(),
                include_tx_body: true,
                accept_public_input_as_proven: None,
                sync_blocks_count: 10,
                pruning_config: None,
            }),
            da: sov_mock_da::MockDaConfig {
                sender_address: [0; 32].into(),
                db_path: "/tmp/da".into(),
            },
            storage: StorageConfig {
                path: "/tmp/rollup".into(),
                db_max_open_files: Some(123),
            },
            rpc: RpcConfig {
                bind_host: "127.0.0.1".to_string(),
                bind_port: 12345,
                max_connections: 500,
                max_request_body_size: 10 * 1024 * 1024,
                max_response_body_size: 10 * 1024 * 1024,
                batch_requests_limit: 50,
                enable_subscriptions: true,
                max_subscriptions_per_connection: 200,
            },
            public_keys: RollupPublicKeys {
                sequencer_public_key: vec![0; 32],
                sequencer_da_pub_key: vec![119; 32],
                prover_da_pub_key: vec![],
            },
        };
        assert_eq!(config, expected);
    }

    #[test]
    fn test_correct_prover_config() {
        let config = r#"
            proving_mode = "skip"
            proof_sampling_number = 500
            enable_recovery = true
        "#;

        let config_file = create_config_from(config);

        let config: BatchProverConfig = from_toml_path(config_file.path()).unwrap();
        let expected = BatchProverConfig {
            proving_mode: ProverGuestRunConfig::Skip,
            proof_sampling_number: 500,
            enable_recovery: true,
        };
        assert_eq!(config, expected);
    }
}
