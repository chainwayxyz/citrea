use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::secp256k1::SecretKey;
use bitcoin_da::helpers::builders::body_builders::{create_inscription_type_0, DaTxs};
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig};
use bitcoin_da::spec::RollupParams;
use bitcoincore_rpc::{Client, RpcApi};
use citrea_e2e::config::BitcoinConfig;
use citrea_e2e::node::NodeKind;
use citrea_primitives::REVEAL_TX_PREFIX;
use reth_tasks::TaskExecutor;
use sov_rollup_interface::Network;

pub(super) enum DaServiceKeyKind {
    #[allow(dead_code)]
    Sequencer,
    BatchProver,
    Other(String),
}

const SEQUENCER_DA_PUBLIC_KEY: &str =
    "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262";
const PROVER_DA_PUBLIC_KEY: &str =
    "56D08C2DDE7F412F80EC99A0A328F76688C904BD4D1435281EFC9270EC8C8707";

pub(super) async fn spawn_bitcoin_da_service(
    task_executor: TaskExecutor,
    da_config: &BitcoinConfig,
    test_dir: PathBuf,
    kind: DaServiceKeyKind,
) -> Arc<BitcoinService> {
    let da_private_key = match kind {
        DaServiceKeyKind::Sequencer => SEQUENCER_DA_PUBLIC_KEY.to_string(),
        DaServiceKeyKind::BatchProver => PROVER_DA_PUBLIC_KEY.to_string(),
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
                network: Network::Nightly,
            },
            tx,
        )
        .await
        .unwrap(),
    );

    task_executor
        .spawn_with_graceful_shutdown_signal(|tk| bitcoin_da_service.clone().run_da_queue(rx, tk));

    bitcoin_da_service
}

pub async fn create_complete_tx_with_prefix(
    client: &Client,
    body: Vec<u8>,
    prefix: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let da_private_key = SecretKey::from_str(PROVER_DA_PUBLIC_KEY).unwrap();
    let change_address = client.get_new_address(None, None).await?.assume_checked();
    let utxos = client
        .list_unspent(None, None, None, None, None)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    let result = create_inscription_type_0(
        body,
        &da_private_key,
        None,
        utxos,
        change_address,
        1,
        1,
        bitcoin::Network::Regtest,
        prefix,
    )?;

    match result {
        DaTxs::Complete { commit, reveal } => {
            let signed_raw_commit_tx = client
                .sign_raw_transaction_with_wallet(&commit, None, None)
                .await?;

            Ok((
                signed_raw_commit_tx.hex,
                bitcoin::consensus::encode::serialize(&reveal.tx),
            ))
        }
        _ => unreachable!("Unexpected result type"),
    }
}
