use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Deserialize;

/// Runner configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RunnerConfig {
    /// DA start height.
    pub start_height: u64,
    /// RPC configuration.
    pub rpc_config: RpcConfig,
}

/// RPC configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RpcConfig {
    /// RPC host.
    pub bind_host: String,
    /// RPC port.
    pub bind_port: u16,
}

/// Simple storage configuration
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct StorageConfig {
    /// Path that can be utilized by concrete implementation
    pub path: PathBuf,
}

/// Sequencer RPC configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SoftConfirmationClientRpcConfig {
    /// Sequencer start height.
    pub start_height: u64,
    /// RPC host url (with port, if applicable).
    pub scc_url: String,
}

/// Rollup Configuration
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RollupConfig<DaServiceConfig> {
    /// Currently rollup config runner only supports storage path parameter
    pub storage: StorageConfig,
    /// Runner own configuration.
    pub runner: RunnerConfig,
    /// Data Availability service configuration.
    pub da: DaServiceConfig,
    /// Soft Confirmation Client RPC Config for sequencer connection
    pub soft_confirmation_client: Option<SoftConfirmationClientRpcConfig>,
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
    use std::path::PathBuf;

    use tempfile::NamedTempFile;

    use super::*;

    fn create_config_from(content: &str) -> NamedTempFile {
        let mut config_file = NamedTempFile::new().unwrap();
        config_file.write_all(content.as_bytes()).unwrap();
        config_file
    }

    #[test]
    fn test_correct_config() {
        let config = r#"
            [da]
            celestia_rpc_auth_token = "SECRET_RPC_TOKEN"
            celestia_rpc_address = "http://localhost:11111/"
            max_celestia_response_body_size = 980
            [storage]
            path = "/tmp"
            [runner]
            start_height = 31337
            [runner.rpc_config]
            bind_host = "127.0.0.1"
            bind_port = 12345
            [soft_confirmation_client]
            start_height = 5
            scc_url = "http://0.0.0.0:12346"
        "#;

        let config_file = create_config_from(config);

        let config: RollupConfig<sov_celestia_adapter::CelestiaConfig> =
            from_toml_path(config_file.path()).unwrap();
        let expected = RollupConfig {
            runner: RunnerConfig {
                start_height: 31337,
                rpc_config: RpcConfig {
                    bind_host: "127.0.0.1".to_string(),
                    bind_port: 12345,
                },
            },

            da: sov_celestia_adapter::CelestiaConfig {
                celestia_rpc_auth_token: "SECRET_RPC_TOKEN".to_string(),
                celestia_rpc_address: "http://localhost:11111/".into(),
                max_celestia_response_body_size: 980,
                celestia_rpc_timeout_seconds: 60,
            },
            storage: StorageConfig {
                path: PathBuf::from("/tmp"),
            },
            soft_confirmation_client: Some(SoftConfirmationClientRpcConfig {
                start_height: 5,
                scc_url: "http://0.0.0.0:12346".to_owned(),
            }),
        };
        assert_eq!(config, expected);
    }
}
