use std::path::PathBuf;

use bitcoin::Network;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinConfig {
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub rpc_user: String,
    pub rpc_password: String,
    pub data_dir: PathBuf,
    pub extra_args: Vec<String>,
    pub network: Network,
    pub docker_image: Option<String>,
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self {
            p2p_port: 0,
            rpc_port: 0,
            rpc_user: "user".to_string(),
            rpc_password: "password".to_string(),
            data_dir: TempDir::new()
                .expect("Failed to create temporary directory")
                .into_path(),
            extra_args: vec![],
            network: Network::Regtest,
            docker_image: Some("ruimarinho/bitcoin-core:latest".to_string()),
        }
    }
}
