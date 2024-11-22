use std::path::PathBuf;
use std::sync::Arc;

use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig};
use bitcoin_da::spec::RollupParams;
use citrea_common::tasks::manager::TaskManager;
use citrea_e2e::config::BitcoinConfig;
use citrea_e2e::node::NodeKind;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};

pub async fn get_service(
    task_manager: &mut TaskManager<()>,
    config: &BitcoinConfig,
) -> Arc<BitcoinService> {
    let node_url = format!(
        "http://127.0.0.1:{}/wallet/{}",
        config.rpc_port,
        NodeKind::Bitcoin
    );

    let runtime_config = BitcoinServiceConfig {
        node_url,
        node_username: config.rpc_user.clone(),
        node_password: config.rpc_password.clone(),
        network: bitcoin::Network::Regtest,
        da_private_key: Some(
            "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(), // Test key, safe to publish
        ),
        tx_backup_dir: get_tx_backup_dir(),
        monitoring: None,
    };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let da_service = BitcoinService::new_without_wallet_check(
        runtime_config,
        RollupParams {
            to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
            to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
        },
        tx,
    )
    .await
    .expect("Error initializing BitcoinService");

    let da_service = Arc::new(da_service);
    task_manager.spawn(|tk| da_service.clone().run_da_queue(rx, tk));

    da_service
}

pub async fn generate_mock_txs(_service: &BitcoinService) {
    todo!()
}

pub fn get_citrea_path() -> PathBuf {
    std::env::var("CITREA_E2E_TEST_BINARY").map_or_else(
        |_| {
            get_workspace_root()
                .join("target")
                .join("debug")
                .join("citrea")
        },
        PathBuf::from,
    )
}

fn get_tx_backup_dir() -> String {
    get_workspace_root()
        .join("resources")
        .join("bitcoin")
        .join("inscription_txs")
        .to_str()
        .unwrap()
        .to_string()
}

fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .expect("Failed to find workspace root")
        .to_path_buf()
}
