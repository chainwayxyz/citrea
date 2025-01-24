use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::bail;
use citrea_pruning::PruningConfig;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sov_stf_runner::ProverGuestRunConfig;

pub trait FromEnv: Sized {
    fn from_env() -> anyhow::Result<Self>;
}

impl FromEnv for PruningConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(PruningConfig {
            distance: std::env::var("PRUNING_DISTANCE")?.parse()?,
        })
    }
}

impl FromEnv for sov_mock_da::MockDaConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            sender_address: std::env::var("SENDER_ADDRESS")?.parse()?,
            db_path: std::env::var("DB_PATH")?.into(),
        })
    }
}

/// Runner configuration.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RunnerConfig {
    /// Sequencer client configuration.
    pub sequencer_client_url: String,
    /// Saves sequencer soft confirmations if set to true
    pub include_tx_body: bool,
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
            sync_blocks_count: std::env::var("SYNC_BLOCKS_COUNT")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_sync_blocks_count),
            pruning_config: PruningConfig::from_env().ok(),
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

impl FromEnv for RpcConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            bind_host: std::env::var("RPC_BIND_HOST")?,
            bind_port: std::env::var("RPC_BIND_PORT")?.parse()?,
            // for the rest of the fields, in case of a parsing error, the default value will be used
            max_connections: std::env::var("RPC_MAX_CONNECTIONS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_max_connections),
            max_request_body_size: std::env::var("RPC_MAX_REQUEST_BODY_SIZE")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_max_request_body_size),
            max_response_body_size: std::env::var("RPC_MAX_RESPONSE_BODY_SIZE")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_max_response_body_size),
            batch_requests_limit: std::env::var("RPC_BATCH_REQUESTS_LIMIT")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_batch_requests_limit),
            enable_subscriptions: std::env::var("RPC_ENABLE_SUBSCRIPTIONS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_enable_subscriptions),
            max_subscriptions_per_connection: std::env::var("RPC_MAX_SUBSCRIPTIONS_PER_CONNECTION")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_max_subscriptions_per_connection),
        })
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

impl FromEnv for StorageConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            path: std::env::var("STORAGE_PATH")?.into(),
            db_max_open_files: std::env::var("DB_MAX_OPEN_FILES")
                .ok()
                .and_then(|val| val.parse().ok()),
        })
    }
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

impl FromEnv for RollupPublicKeys {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            sequencer_public_key: hex::decode(std::env::var("SEQUENCER_PUBLIC_KEY")?)?,
            sequencer_da_pub_key: hex::decode(std::env::var("SEQUENCER_DA_PUB_KEY")?)?,
            prover_da_pub_key: hex::decode(std::env::var("PROVER_DA_PUB_KEY")?)?,
        })
    }
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
    /// Telemetry configuration
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

impl<DaC: FromEnv> FromEnv for FullNodeConfig<DaC> {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            rpc: RpcConfig::from_env()?,
            storage: StorageConfig::from_env()?,
            runner: RunnerConfig::from_env().ok(),
            da: DaC::from_env()?,
            public_keys: RollupPublicKeys::from_env()?,
            telemetry: TelemetryConfig::from_env()?,
        })
    }
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

/// Prover configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LightClientProverConfig {
    /// Prover run mode
    pub proving_mode: ProverGuestRunConfig,
    /// Average number of commitments to prove
    pub proof_sampling_number: usize,
    /// If true prover will try to recover ongoing proving sessions
    pub enable_recovery: bool,
    /// The starting DA block to sync from
    pub initial_da_height: u64,
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

impl Default for LightClientProverConfig {
    fn default() -> Self {
        Self {
            proving_mode: ProverGuestRunConfig::Execute,
            proof_sampling_number: 0,
            enable_recovery: true,
            initial_da_height: 1,
        }
    }
}

impl FromEnv for BatchProverConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(BatchProverConfig {
            proving_mode: serde_json::from_str(&format!("\"{}\"", std::env::var("PROVING_MODE")?))?,
            proof_sampling_number: std::env::var("PROOF_SAMPLING_NUMBER")?.parse()?,
            enable_recovery: std::env::var("ENABLE_RECOVERY")?.parse()?,
        })
    }
}

impl FromEnv for LightClientProverConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(LightClientProverConfig {
            proving_mode: serde_json::from_str(&format!("\"{}\"", std::env::var("PROVING_MODE")?))?,
            proof_sampling_number: std::env::var("PROOF_SAMPLING_NUMBER")?.parse()?,
            enable_recovery: std::env::var("ENABLE_RECOVERY")?.parse()?,
            initial_da_height: std::env::var("INITIAL_DA_HEIGHT")?.parse()?,
        })
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
    /// Fee throttle config
    pub fee_throttle: FeeThrottleConfig,
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
            fee_throttle: FeeThrottleConfig::default(),
        }
    }
}

impl FromEnv for SequencerConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            private_key: std::env::var("PRIVATE_KEY")?,
            min_soft_confirmations_per_commitment: std::env::var(
                "MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT",
            )?
            .parse()?,
            test_mode: std::env::var("TEST_MODE")?.parse()?,
            deposit_mempool_fetch_limit: std::env::var("DEPOSIT_MEMPOOL_FETCH_LIMIT")?.parse()?,
            mempool_conf: SequencerMempoolConfig::from_env()?,
            da_update_interval_ms: std::env::var("DA_UPDATE_INTERVAL_MS")?.parse()?,
            block_production_interval_ms: std::env::var("BLOCK_PRODUCTION_INTERVAL_MS")?.parse()?,
            fee_throttle: FeeThrottleConfig::from_env()?,
        })
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

impl FromEnv for SequencerMempoolConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            pending_tx_limit: std::env::var("PENDING_TX_LIMIT")?.parse()?,
            pending_tx_size: std::env::var("PENDING_TX_SIZE")?.parse()?,
            queue_tx_limit: std::env::var("QUEUE_TX_LIMIT")?.parse()?,
            queue_tx_size: std::env::var("QUEUE_TX_SIZE")?.parse()?,
            base_fee_tx_limit: std::env::var("BASE_FEE_TX_LIMIT")?.parse()?,
            base_fee_tx_size: std::env::var("BASE_FEE_TX_SIZE")?.parse()?,
            max_account_slots: std::env::var("MAX_ACCOUNT_SLOTS")?.parse()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct FeeThrottleConfig {
    #[serde(default = "defaults::capacity_threshold")]
    pub capacity_threshold: f64,
    #[serde(default = "defaults::base_fee_multiplier")]
    pub base_fee_multiplier: f64,
    #[serde(default = "defaults::max_fee_multiplier")]
    pub max_fee_multiplier: f64,
    #[serde(default = "defaults::fee_exponential_factor")]
    pub fee_exponential_factor: f64,
    #[serde(default = "defaults::fee_multiplier_scalar")]
    pub fee_multiplier_scalar: f64,
}

mod defaults {
    // Threshold after which fee start to increase exponentially
    pub const fn capacity_threshold() -> f64 {
        0.50
    }

    // Multiplier used while below CAPACITY_THRESHOLD
    pub const fn base_fee_multiplier() -> f64 {
        1.0
    }

    // Max multiplier over threshold
    pub const fn max_fee_multiplier() -> f64 {
        4.0
    }

    // Exponential factor to adjust steepness of fee rise
    pub const fn fee_exponential_factor() -> f64 {
        4.0
    }

    pub const fn fee_multiplier_scalar() -> f64 {
        10.0
    }
}

impl Default for FeeThrottleConfig {
    fn default() -> Self {
        Self {
            capacity_threshold: defaults::capacity_threshold(),
            base_fee_multiplier: defaults::base_fee_multiplier(),
            max_fee_multiplier: defaults::max_fee_multiplier(),
            fee_exponential_factor: defaults::fee_exponential_factor(),
            fee_multiplier_scalar: defaults::fee_multiplier_scalar(),
        }
    }
}

impl FromEnv for FeeThrottleConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(FeeThrottleConfig {
            capacity_threshold: std::env::var("L1_FEE_CAPACITY_THRESHOLD").map_or_else(
                |_| Ok(defaults::capacity_threshold()),
                |v| v.parse().map_err(Into::<anyhow::Error>::into),
            )?,
            base_fee_multiplier: std::env::var("L1_FEE_BASE_FEE_MULTIPLIER").map_or_else(
                |_| Ok(defaults::base_fee_multiplier()),
                |v| v.parse().map_err(Into::<anyhow::Error>::into),
            )?,
            max_fee_multiplier: std::env::var("L1_FEE_MAX_FEE_MULTIPLIER").map_or_else(
                |_| Ok(defaults::max_fee_multiplier()),
                |v| v.parse().map_err(Into::<anyhow::Error>::into),
            )?,
            fee_exponential_factor: std::env::var("L1_FEE_EXPONENTIAL_FACTOR").map_or_else(
                |_| Ok(defaults::fee_exponential_factor()),
                |v| v.parse().map_err(Into::<anyhow::Error>::into),
            )?,
            fee_multiplier_scalar: std::env::var("L1_FEE_MULTIPLIER_SCALAR").map_or_else(
                |_| Ok(defaults::fee_multiplier_scalar()),
                |v| v.parse().map_err(Into::<anyhow::Error>::into),
            )?,
        })
    }
}

impl FeeThrottleConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(0.0..=1.0).contains(&self.capacity_threshold) {
            bail!(
                "capacity_threshold must be between 0 and 1, got {}",
                self.capacity_threshold
            );
        }

        if self.base_fee_multiplier < 1.0 {
            bail!(
                "base_fee_multiplier must be >= 1.0, got {}",
                self.base_fee_multiplier
            );
        }

        if self.max_fee_multiplier <= self.base_fee_multiplier {
            bail!(
                "max_fee_multiplier must be > base_fee_multiplier ({} <= {})",
                self.max_fee_multiplier,
                self.base_fee_multiplier
            );
        }

        if self.fee_exponential_factor <= 0.0 {
            bail!(
                "fee_exponential_factor must be > 0, got {}",
                self.fee_exponential_factor
            );
        }

        if self.fee_multiplier_scalar <= 0.0 {
            bail!(
                "fee_multiplier_scalar must be > 0, got {}",
                self.fee_multiplier_scalar
            );
        }

        Ok(())
    }
}

/// Telemetry configuration.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// Server host.
    pub bind_host: Option<String>,
    /// Server port.
    pub bind_port: Option<u16>,
}

impl FromEnv for TelemetryConfig {
    fn from_env() -> anyhow::Result<Self> {
        let bind_host = std::env::var("TELEMETRY_BIND_HOST").ok();
        let bind_port = std::env::var("TELEMETRY_BIND_PORT").ok();
        Ok(Self {
            bind_host,
            bind_port: bind_port.map(|p| p.parse()).transpose()?,
        })
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

            [telemetry]
            bind_host = "0.0.0.0"
            bind_port = 8001
        "#.to_owned();

        let config_file = create_config_from(&config);

        let config: FullNodeConfig<sov_mock_da::MockDaConfig> =
            from_toml_path(config_file.path()).unwrap();

        let expected = FullNodeConfig {
            runner: Some(RunnerConfig {
                sequencer_client_url: "http://0.0.0.0:12346".to_owned(),
                include_tx_body: true,
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
            telemetry: TelemetryConfig {
                bind_host: Some("0.0.0.0".to_owned()),
                bind_port: Some(8001),
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
    #[test]
    fn test_correct_sequencer_config() {
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
            [fee_throttle]
            capacity_threshold = 0.5
            base_fee_multiplier = 1.0
            max_fee_multiplier = 4.0
            fee_exponential_factor = 4.0
            fee_multiplier_scalar = 10.0
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
            fee_throttle: FeeThrottleConfig {
                capacity_threshold: 0.5,
                base_fee_multiplier: 1.0,
                max_fee_multiplier: 4.0,
                fee_exponential_factor: 4.0,
                fee_multiplier_scalar: 10.0,
            },
        };
        assert_eq!(config, expected);
    }

    #[test]
    fn test_correct_prover_config_from_env() {
        std::env::set_var("PROVING_MODE", "skip");
        std::env::set_var("PROOF_SAMPLING_NUMBER", "500");
        std::env::set_var("ENABLE_RECOVERY", "true");

        let prover_config = BatchProverConfig::from_env().unwrap();

        let expected = BatchProverConfig {
            proving_mode: ProverGuestRunConfig::Skip,
            proof_sampling_number: 500,
            enable_recovery: true,
        };
        assert_eq!(prover_config, expected);
    }
    #[test]
    fn test_correct_sequencer_config_from_env() {
        std::env::set_var(
            "PRIVATE_KEY",
            "1212121212121212121212121212121212121212121212121212121212121212",
        );
        std::env::set_var("MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT", "123");
        std::env::set_var("TEST_MODE", "false");
        std::env::set_var("DEPOSIT_MEMPOOL_FETCH_LIMIT", "10");
        std::env::set_var("DA_UPDATE_INTERVAL_MS", "1000");
        std::env::set_var("BLOCK_PRODUCTION_INTERVAL_MS", "1000");
        std::env::set_var("PENDING_TX_LIMIT", "100000");
        std::env::set_var("PENDING_TX_SIZE", "200");
        std::env::set_var("QUEUE_TX_LIMIT", "100000");
        std::env::set_var("QUEUE_TX_SIZE", "200");
        std::env::set_var("BASE_FEE_TX_LIMIT", "100000");
        std::env::set_var("BASE_FEE_TX_SIZE", "200");
        std::env::set_var("MAX_ACCOUNT_SLOTS", "16");
        std::env::set_var("L1_FEE_CAPACITY_THRESHOLD", "0.5");
        std::env::set_var("L1_FEE_BASE_FEE_MULTIPLIER", "1.0");
        std::env::set_var("L1_FEE_MAX_FEE_MULTIPLIER", "4.0");
        std::env::set_var("L1_FEE_EXPONENTIAL_FACTOR", "4.0");
        std::env::set_var("L1_FEE_MULTIPLIER_SCALAR", "10.0");

        let sequencer_config = SequencerConfig::from_env().unwrap();

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
            fee_throttle: FeeThrottleConfig {
                capacity_threshold: 0.5,
                base_fee_multiplier: 1.0,
                max_fee_multiplier: 4.0,
                fee_exponential_factor: 4.0,
                fee_multiplier_scalar: 10.0,
            },
        };
        assert_eq!(sequencer_config, expected);
    }

    #[test]
    fn test_correct_full_node_config_from_env() {
        std::env::set_var(
            "SEQUENCER_PUBLIC_KEY",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        std::env::set_var(
            "SEQUENCER_DA_PUB_KEY",
            "7777777777777777777777777777777777777777777777777777777777777777",
        );
        std::env::set_var("PROVER_DA_PUB_KEY", "");

        std::env::set_var("RPC_BIND_HOST", "127.0.0.1");
        std::env::set_var("RPC_BIND_PORT", "12345");
        std::env::set_var("RPC_MAX_CONNECTIONS", "500");
        std::env::set_var("RPC_ENABLE_SUBSCRIPTIONS", "true");
        std::env::set_var("RPC_MAX_SUBSCRIPTIONS_PER_CONNECTION", "200");

        std::env::set_var(
            "SENDER_ADDRESS",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        std::env::set_var("DB_PATH", "/tmp/da");

        std::env::set_var("STORAGE_PATH", "/tmp/rollup");
        std::env::set_var("DB_MAX_OPEN_FILES", "123");

        std::env::set_var("INCLUDE_TX_BODY", "true");
        std::env::set_var("SEQUENCER_CLIENT_URL", "http://0.0.0.0:12346");
        std::env::set_var("PRUNING_DISTANCE", "1000");

        std::env::set_var("TELEMETRY_BIND_HOST", "0.0.0.0");
        std::env::set_var("TELEMETRY_BIND_PORT", "8082");
        let full_node_config: FullNodeConfig<sov_mock_da::MockDaConfig> =
            FullNodeConfig::from_env().unwrap();

        let expected = FullNodeConfig {
            rpc: RpcConfig {
                bind_host: "127.0.0.1".to_string(),
                bind_port: 12345,
                max_connections: 500,
                max_request_body_size: default_max_request_body_size(),
                max_response_body_size: default_max_response_body_size(),
                batch_requests_limit: default_batch_requests_limit(),
                enable_subscriptions: true,
                max_subscriptions_per_connection: 200,
            },
            storage: StorageConfig {
                path: "/tmp/rollup".into(),
                db_max_open_files: Some(123),
            },
            runner: Some(RunnerConfig {
                sequencer_client_url: "http://0.0.0.0:12346".to_string(),
                include_tx_body: true,
                sync_blocks_count: default_sync_blocks_count(),
                pruning_config: Some(PruningConfig { distance: 1000 }),
            }),
            da: sov_mock_da::MockDaConfig {
                sender_address: [0; 32].into(),
                db_path: "/tmp/da".into(),
            },
            public_keys: RollupPublicKeys {
                sequencer_public_key: vec![0; 32],
                sequencer_da_pub_key: vec![119; 32],
                prover_da_pub_key: vec![],
            },
            telemetry: TelemetryConfig {
                bind_host: Some("0.0.0.0".to_owned()),
                bind_port: Some(8082),
            },
        };
        assert_eq!(full_node_config, expected);
    }

    #[test]
    fn test_optional_telemetry_config_from_env() {
        let telemetry_config = TelemetryConfig::from_env().unwrap();

        let expected = TelemetryConfig {
            bind_host: None,
            bind_port: None,
        };
        assert_eq!(telemetry_config, expected);

        std::env::set_var("TELEMETRY_BIND_HOST", "0.0.0.0");
        std::env::set_var("TELEMETRY_BIND_PORT", "5000");
        let telemetry_config = TelemetryConfig::from_env().unwrap();

        let expected = TelemetryConfig {
            bind_host: Some("0.0.0.0".to_owned()),
            bind_port: Some(5000),
        };
        assert_eq!(telemetry_config, expected);
    }
}
