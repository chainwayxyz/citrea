use bitcoin_da::service::BitcoinServiceConfig;
use sov_stf_runner::{FullNodeConfig, RollupPublicKeys, RpcConfig, StorageConfig};
use tempfile::TempDir;

use super::BitcoinConfig;
use crate::bitcoin_e2e::utils::get_tx_backup_dir;
pub type RollupConfig = FullNodeConfig<BitcoinServiceConfig>;

pub fn default_rollup_config() -> RollupConfig {
    RollupConfig {
        rpc: RpcConfig {
            bind_host: "127.0.0.1".into(),
            bind_port: 0,
            max_connections: 100,
            max_request_body_size: 10 * 1024 * 1024,
            max_response_body_size: 10 * 1024 * 1024,
            batch_requests_limit: 50,
            enable_subscriptions: true,
            max_subscriptions_per_connection: 100,
        },
        storage: StorageConfig {
            path: TempDir::new()
                .expect("Failed to create temporary directory")
                .into_path(),
            db_max_open_files: None,
        },
        runner: None,
        da: BitcoinServiceConfig {
            node_url: String::new(),
            node_username: String::from("user"),
            node_password: String::from("password"),
            network: bitcoin::Network::Regtest,
            da_private_key: None,
            tx_backup_dir: get_tx_backup_dir(),
        },
        public_keys: RollupPublicKeys {
            sequencer_public_key: vec![
                32, 64, 64, 227, 100, 193, 15, 43, 236, 156, 31, 229, 0, 161, 205, 76, 36, 124,
                137, 214, 80, 160, 30, 215, 232, 44, 171, 168, 103, 135, 124, 33,
            ],
            // private key [4, 95, 252, 129, 163, 193, 253, 179, 175, 19, 89, 219, 242, 209, 20, 176, 179, 239, 191, 127, 41, 204, 156, 93, 160, 18, 103, 170, 57, 210, 199, 141]
            // Private Key (WIF): KwNDSCvKqZqFWLWN1cUzvMiJQ7ck6ZKqR6XBqVKyftPZtvmbE6YD
            sequencer_da_pub_key: vec![
                3, 136, 195, 18, 11, 187, 25, 37, 38, 109, 184, 237, 247, 208, 131, 219, 162, 70,
                35, 174, 234, 47, 239, 247, 60, 51, 174, 242, 247, 112, 186, 222, 30,
            ],
            // private key [117, 186, 249, 100, 208, 116, 89, 70, 0, 54, 110, 91, 17, 26, 29, 168, 248, 107, 46, 254, 45, 34, 218, 81, 200, 216, 33, 38, 160, 252, 172, 114]
            // Private Key (WIF): L1AZdJXzDGGENBBPZGSL7dKJnwn5xSKqzszgK6CDwiBGThYQEVTo
            prover_da_pub_key: vec![
                2, 138, 232, 157, 214, 46, 7, 210, 235, 33, 105, 239, 71, 169, 105, 233, 239, 84,
                172, 112, 13, 54, 9, 206, 106, 138, 251, 218, 15, 28, 137, 112, 127,
            ],
        },
    }
}

impl From<BitcoinConfig> for BitcoinServiceConfig {
    fn from(v: BitcoinConfig) -> Self {
        Self {
            node_url: format!("127.0.0.1:{}", v.rpc_port),
            node_username: v.rpc_user,
            node_password: v.rpc_password,
            network: v.network,
            da_private_key: None,
            tx_backup_dir: "".to_string(),
        }
    }
}
