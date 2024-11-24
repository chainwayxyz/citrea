use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::Amount;
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig};
use bitcoin_da::spec::block::BitcoinBlock;
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::WITNESS_COMMITMENT_PREFIX;
use bitcoincore_rpc::json::{AddressType, CreateRawTransactionInput, FundRawTransactionOptions};
use bitcoincore_rpc::RpcApi;
use citrea_common::tasks::manager::TaskManager;
use citrea_e2e::bitcoin::BitcoinNode;
use citrea_e2e::config::BitcoinConfig;
use citrea_e2e::node::NodeKind;
use citrea_e2e::traits::NodeT;
use citrea_primitives::{MAX_TXBODY_SIZE, TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use sov_rollup_interface::da::{DaData, SequencerCommitment};
use sov_rollup_interface::services::da::DaService;

const DEFAULT_DA_PRIVATE_KEY: &str =
    "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262";

pub async fn get_default_service(
    task_manager: &mut TaskManager<()>,
    config: &BitcoinConfig,
) -> Arc<BitcoinService> {
    get_service(
        task_manager,
        config,
        NodeKind::Bitcoin.to_string(),
        DEFAULT_DA_PRIVATE_KEY.to_string(),
        TO_BATCH_PROOF_PREFIX.to_vec(),
        TO_LIGHT_CLIENT_PREFIX.to_vec(),
    )
    .await
}

pub async fn get_service(
    task_manager: &mut TaskManager<()>,
    config: &BitcoinConfig,
    wallet: String,
    da_private_key: String,
    to_batch_proof_prefix: Vec<u8>,
    to_light_client_prefix: Vec<u8>,
) -> Arc<BitcoinService> {
    let node_url = format!("http://127.0.0.1:{}/wallet/{}", config.rpc_port, wallet,);

    let runtime_config = BitcoinServiceConfig {
        node_url,
        node_username: config.rpc_user.clone(),
        node_password: config.rpc_password.clone(),
        network: bitcoin::Network::Regtest,
        da_private_key: Some(da_private_key),
        tx_backup_dir: get_tx_backup_dir(),
        monitoring: None,
    };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let da_service = BitcoinService::new_without_wallet_check(
        runtime_config,
        RollupParams {
            to_batch_proof_prefix,
            to_light_client_prefix,
        },
        tx,
    )
    .await
    .expect("Error initializing BitcoinService");

    let da_service = Arc::new(da_service);
    task_manager.spawn(|tk| da_service.clone().run_da_queue(rx, tk));

    da_service
}

/// Generates mock commitment and zk proof transactions and publishes a DA block
/// with all mock transactions in it, and returns the block. Transactions also contain
/// invalid commitment and zk proof transactions.
///
/// In total it generates 28 transactions.
/// - Valid commitments: 3 (6 txs)
/// - Valid complete proofs: 2 (4 txs)
/// - Valid chunked proofs: 1 with 2 chunks (6 txs) + 1 with 3 chunks (8 txs)
/// - Invalid commitment with wrong public key: 1 (2 txs)
/// - Invalid commitment with wrong prefix: 1 (2 txs)
///
/// With coinbase transaction, returned block has total of 29 transactions.
pub async fn generate_mock_txs(
    da_service: &BitcoinService,
    da_node: &BitcoinNode,
    task_manager: &mut TaskManager<()>,
) -> BitcoinBlock {
    // Funding wallet requires block generation, hence we do funding at the beginning
    // to be able to write all transactions into the same block.
    let wrong_prefix_wallet = "wrong_prefix".to_string();
    create_and_fund_wallet(wrong_prefix_wallet.clone(), da_node).await;
    let wrong_prefix_da_service = get_service(
        task_manager,
        &da_node.config,
        wrong_prefix_wallet,
        DEFAULT_DA_PRIVATE_KEY.to_string(),
        vec![5],
        vec![6],
    )
    .await;

    let wrong_key_wallet = "wrong_key".to_string();
    create_and_fund_wallet(wrong_key_wallet.clone(), da_node).await;
    let wrong_key_da_service = get_service(
        task_manager,
        &da_node.config,
        wrong_key_wallet,
        "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33263".to_string(),
        TO_BATCH_PROOF_PREFIX.to_vec(),
        TO_LIGHT_CLIENT_PREFIX.to_vec(),
    )
    .await;

    // Generate 100 blocks for wallets to get their rewards
    finalize_funds(da_node).await;

    da_service
        .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
            merkle_root: [13; 32],
            l2_start_block_number: 1002,
            l2_end_block_number: 1100,
        }))
        .await
        .expect("Failed to send transaction");

    da_service
        .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
            merkle_root: [14; 32],
            l2_start_block_number: 1101,
            l2_end_block_number: 1245,
        }))
        .await
        .expect("Failed to send transaction");

    let size = 2000;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    da_service
        .send_transaction(DaData::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Invoke chunked zk proof generation with 2 chunks
    let size = MAX_TXBODY_SIZE + 1500;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    da_service
        .send_transaction(DaData::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Sequencer commitment with wrong tx prefix
    wrong_prefix_da_service
        .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
            merkle_root: [15; 32],
            l2_start_block_number: 1246,
            l2_end_block_number: 1268,
        }))
        .await
        .expect("Failed to send transaction");

    let size = 1024;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    da_service
        .send_transaction(DaData::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Sequencer commitment with wrong key and signature
    wrong_key_da_service
        .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
            merkle_root: [15; 32],
            l2_start_block_number: 1246,
            l2_end_block_number: 1268,
        }))
        .await
        .expect("Failed to send transaction");

    da_service
        .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
            merkle_root: [15; 32],
            l2_start_block_number: 1246,
            l2_end_block_number: 1268,
        }))
        .await
        .expect("Failed to send transaction");

    // Invoke chunked zk proof generation with 3 chunks
    let size = MAX_TXBODY_SIZE * 2 + 2500;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    da_service
        .send_transaction(DaData::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Write all txs to a block
    let block_hash = da_node.generate(1).await.unwrap()[0];

    let block = da_service.get_block_by_hash(block_hash).await.unwrap();
    assert_eq!(block.txdata.len(), 29);

    block
}

// TODO: make this work
pub async fn generate_nonsegwit_block(
    da_node: &BitcoinNode,
    da_service: &BitcoinService,
) -> BitcoinBlock {
    let client = da_node.client();
    let address = client
        .get_new_address(Some("nonsegwit_address"), Some(AddressType::Legacy))
        .await
        .unwrap()
        .assume_checked();

    client.generate_to_address(5, &address).await.unwrap();
    finalize_funds(da_node).await;

    let utxos = client
        .list_unspent(Some(0), None, Some(&[&address]), None, None)
        .await
        .unwrap();
    assert_eq!(utxos.len(), 5);

    let input = CreateRawTransactionInput {
        txid: utxos[0].txid,
        vout: utxos[0].vout,
        sequence: None,
    };
    let mut output = HashMap::new();
    output.insert(address.to_string(), utxos[0].amount / 2);
    output.insert(address.to_string(), utxos[0].amount / 2);

    let raw_tx = client
        .create_raw_transaction(&[input], &output, None, None)
        .await
        .unwrap();

    let funded_tx = client
        .fund_raw_transaction(
            &raw_tx,
            Some(&FundRawTransactionOptions {
                change_address: Some(address.clone()),
                fee_rate: Some(Amount::ONE_SAT * 1000),
                ..Default::default()
            }),
            None,
        )
        .await
        .unwrap();

    let signed_tx = client
        .sign_raw_transaction_with_wallet(&funded_tx.hex, None, None)
        .await
        .unwrap();

    client.send_raw_transaction(&signed_tx.hex).await.unwrap();

    let block_hash = da_node.generate(1).await.unwrap()[0];

    let block = da_service.get_block_by_hash(block_hash).await.unwrap();
    let txs = block.txdata.as_slice();

    // ensure that block does not have any segwit txs
    let idx = txs[0].output.iter().position(|output| {
        output
            .script_pubkey
            .to_bytes()
            .starts_with(WITNESS_COMMITMENT_PREFIX)
    });
    assert_eq!(idx, None);

    block
}

/// Creates and funds a wallet. Funds are not finalized until `finalize_funds` is called.
async fn create_and_fund_wallet(wallet: String, da_node: &BitcoinNode) {
    da_node
        .client()
        .create_wallet(&wallet, None, None, None, None)
        .await
        .unwrap();

    da_node.fund_wallet(wallet, 5).await.unwrap();
}

/// Generates 100 blocks and finalizes funds
async fn finalize_funds(da_node: &BitcoinNode) {
    da_node.generate(100).await.unwrap();
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

// For some reason, even though macro is used, it sees it as unused
#[allow(unused)]
pub mod macros {
    macro_rules! assert_panic {
        // Match a single expression
        ($expr:expr) => {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $expr)) {
                Ok(_) => panic!("Expression did not trigger panic"),
                Err(_) => (),
            }
        };
        // Match an expression and an expected message
        ($expr:expr, $expected_msg:expr) => {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $expr)) {
                Ok(_) => panic!("Expression did not trigger panic"),
                Err(err) => {
                    let expected_msg = $expected_msg;
                    if let Some(msg) = err.downcast_ref::<&str>() {
                        assert!(
                            msg.contains(expected_msg),
                            "Panic message '{}' does not match expected '{}'",
                            msg,
                            expected_msg
                        );
                    } else if let Some(msg) = err.downcast_ref::<String>() {
                        assert!(
                            msg.contains(expected_msg),
                            "Panic message '{}' does not match expected '{}'",
                            msg,
                            expected_msg
                        );
                    } else {
                        panic!(
                            "Panic occurred, but message does not match expected '{}'",
                            expected_msg
                        );
                    }
                }
            }
        };
    }

    pub(crate) use assert_panic;
}
