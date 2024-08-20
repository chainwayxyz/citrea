use bitcoin_da::service::DaServiceConfig;
use sov_stf_runner::{FullNodeConfig, RollupPublicKeys, RpcConfig, StorageConfig};
use tempfile::TempDir;

use super::BitcoinConfig;
pub type RollupConfig = FullNodeConfig<DaServiceConfig>;

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
        },
        runner: None,
        da: DaServiceConfig {
            node_url: String::new(),
            node_username: String::from("user"),
            node_password: String::from("password"),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(),
            ),
            fee_rates_to_avg: None,
        },
        public_keys: RollupPublicKeys {
            sequencer_public_key: vec![
                32, 64, 64, 227, 100, 193, 15, 43, 236, 156, 31, 229, 0, 161, 205, 76, 36, 124,
                137, 214, 80, 160, 30, 215, 232, 44, 171, 168, 103, 135, 124, 33,
            ],
            sequencer_da_pub_key: vec![0; 32],
            prover_da_pub_key: vec![0; 32],
        },
        sync_blocks_count: 10,
    }
}

impl From<BitcoinConfig> for DaServiceConfig {
    fn from(v: BitcoinConfig) -> Self {
        Self {
            node_url: format!("127.0.0.1:{}", v.rpc_port),
            node_username: v.rpc_user,
            node_password: v.rpc_password,
            network: v.network,
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(),
            ),
            fee_rates_to_avg: None,
        }
    }
}
