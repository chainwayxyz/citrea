use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use citrea_pruning::PruningConfig;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sov_stf_runner::ProverGuestRunConfig;

pub trait FromEnv: Sized {
    fn from_env() -> anyhow::Result<Self>;
}
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
impl FromEnv for RunnerConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            sequencer_client_url: std::env::var("SEQUENCER_CLIENT_URL")?,
            include_tx_body: std::env::var("INCLUDE_TX_BODY")?.parse()?,
            accept_public_input_as_proven: std::env::var("ACCEPT_PUBLIC_INPUT_AS_PROVEN")
                .ok()
                .map(|val| val.parse().ok())
                .flatten(),
            sync_blocks_count: toml::from_str(&std::env::var("SYNC_BLOCKS_COUNT").unwrap_or("".to_string()))?,
            pruning_config: std::env::var("PRUNING_CONFIG")
                .ok()
                .map(|val| toml::from_str(&val).ok())
                .flatten(),
        })
    }
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
impl FromEnv for RpcConfig{
    fn from_env() -> anyhow::Result<Self> {
        let mut toml_string = "".to_string();
        toml_string.push_str(&format!("bind_host = {}\n", std::env::var("RPC_BIND_HOST")?));
        toml_string.push_str(&format!("bind_port = {}\n", std::env::var("RPC_BIND_PORT")?));
        if let Ok(val) = std::env::var("RPC_MAX_CONNECTIONS") {
            toml_string.push_str(&format!("max_connections = {}\n", val));
        }
        if let Ok(val) = std::env::var("RPC_MAX_REQUEST_BODY_SIZE") {
            toml_string.push_str(&format!("max_request_body_size = {}\n", val));
        }
        if let Ok(val) = std::env::var("RPC_MAX_RESPONSE_BODY_SIZE") {
            toml_string.push_str(&format!("max_response_body_size = {}\n", val));
        }
        if let Ok(val) = std::env::var("RPC_BATCH_REQUESTS_LIMIT") {
            toml_string.push_str(&format!("batch_requests_limit = {}\n", val));
        }
        if let Ok(val) = std::env::var("RPC_ENABLE_SUBSCRIPTIONS") {
            toml_string.push_str(&format!("enable_subscriptions = {}\n", val));
        }
        if let Ok(val) = std::env::var("RPC_MAX_SUBSCRIPTIONS_PER_CONNECTION") {
            toml_string.push_str(&format!("max_subscriptions_per_connection = {}\n", val));
        }
        Ok(toml::from_str(&toml_string)?)
    }
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
pub struct ProverConfig {
    /// Prover run mode
    pub proving_mode: ProverGuestRunConfig,
    /// Average number of commitments to prove
    pub proof_sampling_number: usize,
    /// If true prover will try to recover ongoing proving sessions
    pub enable_recovery: bool,
}

impl Default for ProverConfig {
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

/// Rollup Configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SequencerConfig {
    /// Private key of the sequencer
    pub private_key: String,
    /// Min. soft confirmaitons for sequencer to commit
    pub min_soft_confirmations_per_commitment: u64,
    /// Whether or not the sequencer is running in test mode
    pub test_mode: bool,
    /// Limit for the number of deposit transactions to be included in the block
    pub deposit_mempool_fetch_limit: usize,
    /// Sequencer specific mempool config
    pub mempool_conf: SequencerMempoolConfig,
    /// DA layer update loop interval in ms
    pub da_update_interval_ms: u64,
    /// Block production interval in ms
    pub block_production_interval_ms: u64,
}

impl Default for SequencerConfig {
    fn default() -> Self {
        SequencerConfig {
            private_key: "1212121212121212121212121212121212121212121212121212121212121212"
                .to_string(),
            min_soft_confirmations_per_commitment: 4,
            test_mode: true,
            deposit_mempool_fetch_limit: 10,
            block_production_interval_ms: 100,
            da_update_interval_ms: 100,
            mempool_conf: Default::default(),
        }
    }
}

/// Mempool Config for the sequencer
/// Read: https://github.com/ledgerwatch/erigon/wiki/Transaction-Pool-Design
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SequencerMempoolConfig {
    /// Max number of transactions in the pending sub-pool
    pub pending_tx_limit: u64,
    /// Max megabytes of transactions in the pending sub-pool
    pub pending_tx_size: u64,
    /// Max number of transactions in the queued sub-pool
    pub queue_tx_limit: u64,
    /// Max megabytes of transactions in the queued sub-pool
    pub queue_tx_size: u64,
    /// Max number of transactions in the base-fee sub-pool
    pub base_fee_tx_limit: u64,
    /// Max megabytes of transactions in the base-fee sub-pool
    pub base_fee_tx_size: u64,
    /// Max number of executable transaction slots guaranteed per account
    pub max_account_slots: u64,
}

impl Default for SequencerMempoolConfig {
    fn default() -> Self {
        Self {
            pending_tx_limit: 100000,
            pending_tx_size: 200,
            queue_tx_limit: 100000,
            queue_tx_size: 200,
            base_fee_tx_limit: 100000,
            base_fee_tx_size: 200,
            max_account_slots: 16,
        }
    }
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

        let config: ProverConfig = from_toml_path(config_file.path()).unwrap();
        let expected = ProverConfig {
            proving_mode: ProverGuestRunConfig::Skip,
            proof_sampling_number: 500,
            enable_recovery: true,
        };
        assert_eq!(config, expected);
    }
    #[test]
    fn test_correct_config_sequencer() {
        let config = r#"
            private_key = "1212121212121212121212121212121212121212121212121212121212121212"
            min_soft_confirmations_per_commitment = 123
            test_mode = false
            deposit_mempool_fetch_limit = 10
            da_update_interval_ms = 1000
            block_production_interval_ms = 1000
            [mempool_conf]
            pending_tx_limit = 100000
            pending_tx_size = 200
            queue_tx_limit = 100000
            queue_tx_size = 200
            base_fee_tx_limit = 100000
            base_fee_tx_size = 200
            max_account_slots = 16
        "#;

        let config_file = create_config_from(config);

        let config: SequencerConfig = from_toml_path(config_file.path()).unwrap();

        let expected = SequencerConfig {
            private_key: "1212121212121212121212121212121212121212121212121212121212121212"
                .to_string(),
            min_soft_confirmations_per_commitment: 123,
            test_mode: false,
            deposit_mempool_fetch_limit: 10,
            mempool_conf: SequencerMempoolConfig {
                pending_tx_limit: 100000,
                pending_tx_size: 200,
                queue_tx_limit: 100000,
                queue_tx_size: 200,
                base_fee_tx_limit: 100000,
                base_fee_tx_size: 200,
                max_account_slots: 16,
            },
            da_update_interval_ms: 1000,
            block_production_interval_ms: 1000,
        };
        assert_eq!(config, expected);
    }
    #[test]
    fn test_read_rpc_config_from_env(){
        std::env::set_var("RPC_BIND_HOST", "\"127.0.0.1\"");
        std::env::set_var("RPC_BIND_PORT", "8080");
        std::env::set_var("RPC_MAX_CONNECTIONS", "100");
        let rpc_config = RpcConfig::from_env().unwrap();

        let expected = RpcConfig {
            bind_host: "127.0.0.1".to_string(),
            bind_port: 8080,
            max_connections: 50,
            max_request_body_size: default_max_request_body_size(),
            max_response_body_size: default_max_response_body_size(),
            batch_requests_limit: default_batch_requests_limit(),
            enable_subscriptions: default_enable_subscriptions(),
            max_subscriptions_per_connection: default_max_subscriptions_per_connection(),
        };
        assert_eq!(rpc_config, expected);
    }
    #[test]
    fn test_read_runner_config_from_env() {
        std::env::set_var("SEQUENCER_CLIENT_URL", "\"http://localhost:8545\"");
        std::env::set_var("INCLUDE_TX_BODY", "true");
        std::env::set_var("ACCEPT_PUBLIC_INPUT_AS_PROVEN", "true");
        std::env::set_var("SYNC_BLOCKS_COUNT", "100");
        let runner_config = RunnerConfig::from_env().unwrap();

        let expected = RunnerConfig {
            sequencer_client_url: "http://localhost:8545".to_string(),
            include_tx_body: true,
            accept_public_input_as_proven: Some(true),
            sync_blocks_count: 100,
            pruning_config: None,
        };

        assert_eq!(runner_config, expected);
    }
}
