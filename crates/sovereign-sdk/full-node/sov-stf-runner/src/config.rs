use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Deserialize;
use shared_backup_db::SharedBackupDbConfig;

use crate::ProverGuestRunConfig;

/// Runner configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RunnerConfig {
    /// Sequencer client configuration.
    pub sequencer_client_url: String,
    /// Saves sequencer soft batches if set to true
    pub include_tx_body: bool,
    /// Only true for tests
    pub accept_public_input_as_proven: Option<bool>,
}

/// RPC configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RpcConfig {
    /// RPC host.
    pub bind_host: String,
    /// RPC port.
    pub bind_port: u16,
    /// Maximum number of concurrent requests.
    /// if not set defaults to 100.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[inline]
const fn default_max_connections() -> u32 {
    100
}

/// Simple storage configuration
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct StorageConfig {
    /// Path that can be utilized by concrete rollup implementation
    pub rollup_path: PathBuf,
    /// Path that can be utilized by concrete DA implementation
    pub da_path: PathBuf,
}

/// Important public keys for the rollup
#[derive(Debug, Clone, PartialEq, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RollupConfig<DaServiceConfig> {
    /// RPC configuration
    pub rpc: RpcConfig,
    /// Currently rollup config runner only supports storage path parameter
    pub storage: StorageConfig,
    /// Runner own configuration.
    pub runner: Option<RunnerConfig>, // optional bc sequencer doesn't need it
    /// Data Availability service configuration.
    pub da: DaServiceConfig,
    /// Important pubkeys
    pub public_keys: RollupPublicKeys,
}

/// Prover configuration
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ProverConfig {
    /// Prover run mode
    pub proving_mode: ProverGuestRunConfig,
    /// Average number of commitments to prove
    pub proof_sampling_number: usize,
    /// Offchain db config
    pub db_config: Option<SharedBackupDbConfig>,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            proving_mode: ProverGuestRunConfig::Execute,
            proof_sampling_number: 0,
            db_config: None,
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
        let tmpdir = tempfile::tempdir().unwrap();
        let rollup_path = tmpdir.path().join("rollup").to_path_buf();
        let da_path = tmpdir.path().join("da").to_path_buf();
        let config = format!(
            r#"
            [public_keys]
            sequencer_public_key = "0000000000000000000000000000000000000000000000000000000000000000"
            sequencer_da_pub_key = "7777777777777777777777777777777777777777777777777777777777777777"
            prover_da_pub_key = ""
            
            [rpc]
            bind_host = "127.0.0.1"
            bind_port = 12345
            max_connections = 500

            [da]
            sender_address = "0000000000000000000000000000000000000000000000000000000000000000"
            
            [storage]
            rollup_path = {:?}
            da_path = {:?}
            
            [runner]
            include_tx_body = true
            sequencer_client_url = "http://0.0.0.0:12346"
        "#,
            rollup_path, da_path
        );

        let config_file = create_config_from(&config);

        let config: RollupConfig<sov_mock_da::MockDaConfig> =
            from_toml_path(config_file.path()).unwrap();

        let storage_path = tmpdir.path();

        let expected = RollupConfig {
            runner: Some(RunnerConfig {
                sequencer_client_url: "http://0.0.0.0:12346".to_owned(),
                include_tx_body: true,
                accept_public_input_as_proven: None,
            }),
            da: sov_mock_da::MockDaConfig {
                sender_address: [0; 32].into(),
            },
            storage: StorageConfig {
                rollup_path: storage_path.join("rollup").to_path_buf(),
                da_path: storage_path.join("da").to_path_buf(),
            },
            rpc: RpcConfig {
                bind_host: "127.0.0.1".to_string(),
                bind_port: 12345,
                max_connections: 500,
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

            [db_config]
            db_host = "localhost"
            db_port = 5432
            db_user = "postgres"
            db_password = "postgres"
            db_name = "postgres"
        "#;

        let config_file = create_config_from(config);

        let config: ProverConfig = from_toml_path(config_file.path()).unwrap();
        let expected = ProverConfig {
            proving_mode: ProverGuestRunConfig::Skip,
            proof_sampling_number: 500,
            db_config: Some(SharedBackupDbConfig::default()),
        };
        assert_eq!(config, expected);
    }
}
