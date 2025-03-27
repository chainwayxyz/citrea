use std::path::PathBuf;
use std::sync::Arc;

use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig};
use bitcoin_da::spec::RollupParams;
use citrea_common::tasks::manager::{TaskManager, TaskType};
use citrea_e2e::config::BitcoinConfig;
use citrea_e2e::node::NodeKind;
use citrea_primitives::REVEAL_TX_PREFIX;

pub(super) enum DaServiceKeyKind {
    #[allow(dead_code)]
    Sequencer,
    BatchProver,
    Other(String),
}

pub(super) async fn spawn_bitcoin_da_service(
    task_manager: &mut TaskManager<()>,
    da_config: &BitcoinConfig,
    test_dir: PathBuf,
    kind: DaServiceKeyKind,
) -> Arc<BitcoinService> {
    let da_private_key = match kind {
        DaServiceKeyKind::Sequencer => {
            "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string()
        }
        DaServiceKeyKind::BatchProver => {
            "56D08C2DDE7F412F80EC99A0A328F76688C904BD4D1435281EFC9270EC8C8707".to_string()
        }
        DaServiceKeyKind::Other(key) => key,
    };

    let bitcoin_da_service_config = BitcoinServiceConfig {
        node_url: format!(
            "http://127.0.0.1:{}/wallet/{}",
            da_config.rpc_port,
            NodeKind::Bitcoin
        ),
        node_username: da_config.rpc_user.clone(),
        node_password: da_config.rpc_password.clone(),
        network: bitcoin::Network::Regtest,
        da_private_key: Some(da_private_key),
        tx_backup_dir: test_dir.join("tx_backup_dir").display().to_string(),
        monitoring: Default::default(),
        mempool_space_url: None,
    };
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let bitcoin_da_service = Arc::new(
        BitcoinService::new_with_wallet_check(
            bitcoin_da_service_config,
            RollupParams {
                reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
            },
            tx,
        )
        .await
        .unwrap(),
    );

    task_manager.spawn(TaskType::Secondary, |tk| {
        bitcoin_da_service.clone().run_da_queue(rx, tk)
    });

    bitcoin_da_service
}
