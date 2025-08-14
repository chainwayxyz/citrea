use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::consensus::{SignableTransaction as _, TxLegacy};
use alloy::network::TxSigner as _;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer as _;
use alloy_primitives::ruint::aliases::U256;
use alloy_primitives::{Bytes, TxKind, U64};
use anyhow::bail;
use bitcoin_da::fee::FeeService;
use bitcoin_da::monitoring::{MonitoringConfig, MonitoringService};
use bitcoin_da::network_constants::get_network_constants;
use bitcoin_da::service::{network_to_bitcoin_network, BitcoinService, BitcoinServiceConfig};
use bitcoin_da::spec::block::BitcoinBlock;
use bitcoin_da::spec::RollupParams;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_e2e::bitcoin::BitcoinNode;
use citrea_e2e::config::BitcoinConfig;
use citrea_e2e::node::{BatchProver, FullNode, NodeKind};
use citrea_e2e::traits::NodeT;
use citrea_primitives::{MAX_TX_BODY_SIZE, REVEAL_TX_PREFIX};
use reth_tasks::TaskExecutor;
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::da::{BatchProofMethodId, DaTxRequest, SequencerCommitment};
use sov_rollup_interface::rpc::{JobRpcResponse, VerifiedBatchProofResponse};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::Network;
use tokio::time::sleep;
use uuid::Uuid;

pub enum DaServiceKeyKind {
    #[allow(dead_code)]
    Sequencer,
    BatchProver,
    Other(String),
}

pub const SEQUENCER_DA_PRIVATE_KEY: &str =
    "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262";
pub const PROVER_DA_PRIVATE_KEY: &str =
    "56D08C2DDE7F412F80EC99A0A328F76688C904BD4D1435281EFC9270EC8C8707";

fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .expect("Failed to find workspace root")
        .to_path_buf()
}

fn get_tx_backup_dir() -> PathBuf {
    get_workspace_root()
        .join("resources")
        .join("bitcoin")
        .join("inscription_txs")
        .to_path_buf()
}

pub async fn get_default_service(
    task_executor: &TaskExecutor,
    config: &BitcoinConfig,
) -> Arc<BitcoinService> {
    spawn_bitcoin_da_service(
        task_executor,
        config,
        get_tx_backup_dir(),
        DaServiceKeyKind::Sequencer,
        REVEAL_TX_PREFIX.to_vec(),
    )
    .await
}

pub async fn spawn_bitcoin_da_sequencer_service(
    task_executor: &TaskExecutor,
    config: &BitcoinConfig,
    dir: PathBuf,
) -> Arc<BitcoinService> {
    spawn_bitcoin_da_service(
        task_executor,
        config,
        dir,
        DaServiceKeyKind::Sequencer,
        REVEAL_TX_PREFIX.to_vec(),
    )
    .await
}

pub async fn spawn_bitcoin_da_prover_service(
    task_executor: &TaskExecutor,
    config: &BitcoinConfig,
    dir: PathBuf,
) -> Arc<BitcoinService> {
    spawn_bitcoin_da_service(
        task_executor,
        config,
        dir,
        DaServiceKeyKind::BatchProver,
        REVEAL_TX_PREFIX.to_vec(),
    )
    .await
}

pub async fn spawn_bitcoin_da_service(
    task_executor: &TaskExecutor,
    da_config: &BitcoinConfig,
    test_dir: PathBuf,
    kind: DaServiceKeyKind,
    reveal_tx_prefix: Vec<u8>,
) -> Arc<BitcoinService> {
    let da_private_key = match kind {
        DaServiceKeyKind::Sequencer => SEQUENCER_DA_PRIVATE_KEY.to_string(),
        DaServiceKeyKind::BatchProver => PROVER_DA_PRIVATE_KEY.to_string(),
        DaServiceKeyKind::Other(key) => key,
    };

    let da_config = BitcoinServiceConfig {
        node_url: format!(
            "http://127.0.0.1:{}/wallet/{}",
            da_config.rpc_port,
            NodeKind::Bitcoin
        ),
        node_username: da_config.rpc_user.clone(),
        node_password: da_config.rpc_password.clone(),
        da_private_key: Some(da_private_key),
        tx_backup_dir: test_dir.join("tx_backup_dir").display().to_string(),
        monitoring: Some(MonitoringConfig {
            check_interval: 1,
            history_limit: 1_000,
            max_history_size: 200_000_000,
            max_rebroadcast_attempts: 5,
            rebroadcast_delay: 1,
        }),
        mempool_space_url: None,
    };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let network = Network::Nightly;
    let chain_params = RollupParams {
        reveal_tx_prefix,
        network,
    };

    let client = Arc::new(
        Client::new(
            &da_config.node_url,
            Auth::UserPass(
                da_config.node_username.clone(),
                da_config.node_password.clone(),
            ),
        )
        .await
        .unwrap(),
    );

    let network = network_to_bitcoin_network(&chain_params.network);
    let network_constants = get_network_constants(&network);
    let (monitoring_service, block_rx) = MonitoringService::new(
        client.clone(),
        da_config.monitoring.clone(),
        network_constants.finality_depth,
    );
    let monitoring_service = Arc::new(monitoring_service);

    let fee_service = FeeService::new(client.clone(), network, da_config.mempool_space_url.clone());

    let service = Arc::new(
        BitcoinService::from_config(
            &da_config,
            chain_params,
            client,
            network,
            network_constants,
            monitoring_service,
            fee_service,
            true,
            tx,
        )
        .await
        .unwrap(),
    );

    task_executor
        .spawn_with_graceful_shutdown_signal(|tk| service.clone().run_da_queue(rx, block_rx, tk));

    service.monitoring.restore().await.unwrap();
    task_executor.spawn_with_graceful_shutdown_signal(|tk| Arc::clone(&service.monitoring).run(tk));

    service
}

pub async fn wait_for_zkproofs(
    full_node: &FullNode,
    height: u64,
    timeout: Option<Duration>,
    count: usize,
) -> anyhow::Result<Vec<VerifiedBatchProofResponse>> {
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(240));

    loop {
        if start.elapsed() >= timeout {
            bail!("FullNode failed to get zkproofs within the specified timeout");
        }

        match full_node
            .client
            .http_client()
            .get_verified_batch_proofs_by_slot_height(U64::from(height))
            .await?
        {
            Some(proofs) => {
                if proofs.len() >= count {
                    return Ok(proofs);
                }
            }
            None => sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Wait for prover job to finish.
pub async fn wait_for_prover_job(
    batch_prover: &BatchProver,
    job_id: Uuid,
    timeout: Option<Duration>,
) -> anyhow::Result<JobRpcResponse> {
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(300));
    loop {
        let response = batch_prover
            .client
            .http_client()
            .get_proving_job(job_id)
            .await?;
        if let Some(response) = response {
            if let Some(proof) = &response.proof {
                if proof.l1_tx_id.is_some() {
                    return Ok(response);
                }
            }
        }

        let now = Instant::now();
        if start + timeout <= now {
            bail!("Timeout. Failed to get prover job {}", job_id);
        }

        sleep(Duration::from_secs(1)).await;
    }
}

pub async fn wait_for_prover_job_count(
    batch_prover: &BatchProver,
    count: usize,
    timeout: Option<Duration>,
) -> anyhow::Result<Vec<Uuid>> {
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(240));

    loop {
        if start.elapsed() >= timeout {
            bail!(
                "BatchProver failed to reach proving job count {} on time",
                count
            );
        }

        let jobs = batch_prover
            .client
            .http_client()
            .get_proving_jobs(count)
            .await
            .unwrap();
        if jobs.len() >= count {
            let job_ids = jobs.into_iter().map(|j| j.job_id).collect();
            return Ok(job_ids);
        }

        sleep(Duration::from_millis(500)).await;
    }
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

/// Generates mock commitment and zk proof transactions and publishes a DA block
/// with all mock transactions in it, and returns the block, valid commitments and proofs.
/// Transactions also contain invalid commitment and zk proof transactions.
///
/// In total it generates 28 transactions.
/// - Valid commitments: 3 (6 txs)
/// - Valid complete proofs: 2 (4 txs)
/// - Valid chunked proofs: 1 with 2 chunks (6 txs) + 1 with 3 chunks (8 txs)
/// - Valid method id txs: 2 (4 txs)
/// - Invalid commitment with wrong public key: 1 (2 txs)
/// - Invalid commitment with wrong prefix: 1 (2 txs)
///
/// With coinbase transaction, returned block has total of 33 transactions.
pub async fn generate_mock_txs(
    da_service: &BitcoinService,
    da_node: &BitcoinNode,
    task_executor: &TaskExecutor,
) -> (
    BitcoinBlock,
    Vec<SequencerCommitment>,
    Vec<Vec<u8>>,
    Vec<BatchProofMethodId>,
) {
    // Funding wallet requires block generation, hence we do funding at the beginning
    // to be able to write all transactions into the same block.
    let prefix_str = "wrong_prefix";
    let wrong_prefix_wallet = PathBuf::from_str(prefix_str).unwrap();
    create_and_fund_wallet(prefix_str.to_string(), da_node).await;
    let wrong_prefix_da_service = spawn_bitcoin_da_service(
        task_executor,
        &da_node.config,
        wrong_prefix_wallet,
        DaServiceKeyKind::Sequencer,
        vec![6],
    )
    .await;

    let wrong_key_str = "wrong_key";
    let wrong_key_wallet = PathBuf::from_str(wrong_key_str).unwrap();
    create_and_fund_wallet(wrong_key_str.to_string(), da_node).await;
    let wrong_key_da_service = spawn_bitcoin_da_service(
        task_executor,
        &da_node.config,
        wrong_key_wallet,
        DaServiceKeyKind::Other(
            "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33263".to_string(),
        ),
        REVEAL_TX_PREFIX.to_vec(),
    )
    .await;

    // Generate 100 blocks for wallets to get their rewards
    finalize_funds(da_node).await;

    let mut valid_commitments = vec![];
    let mut valid_proofs = vec![];
    let mut valid_method_ids = vec![];
    let mut seq_index = 1;

    // Send method id update tx
    let method_id = BatchProofMethodId {
        method_id: [0; 8],
        activation_l2_height: 0,
    };
    valid_method_ids.push(method_id.clone());
    da_service
        .send_transaction(DaTxRequest::BatchProofMethodId(method_id))
        .await
        .expect("Failed to send transaction");

    let commitment = SequencerCommitment {
        merkle_root: [13; 32],
        index: seq_index,
        l2_end_block_number: 1100,
    };
    seq_index += 1;
    valid_commitments.push(commitment.clone());
    da_service
        .send_transaction(DaTxRequest::SequencerCommitment(commitment))
        .await
        .expect("Failed to send transaction");

    let commitment = SequencerCommitment {
        merkle_root: [14; 32],
        index: seq_index,
        l2_end_block_number: 1245,
    };
    seq_index += 1;
    valid_commitments.push(commitment.clone());
    da_service
        .send_transaction(DaTxRequest::SequencerCommitment(commitment))
        .await
        .expect("Failed to send transaction");

    let size = 2000;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    valid_proofs.push(blob.clone());
    da_service
        .send_transaction(DaTxRequest::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Invoke chunked zk proof generation with 2 chunks
    let size = MAX_TX_BODY_SIZE + 1500;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    valid_proofs.push(blob.clone());
    da_service
        .send_transaction(DaTxRequest::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Sequencer commitment with wrong tx prefix
    wrong_prefix_da_service
        .send_transaction(DaTxRequest::SequencerCommitment(SequencerCommitment {
            merkle_root: [15; 32],
            index: seq_index,
            l2_end_block_number: 1268,
        }))
        .await
        .expect("Failed to send transaction");

    let size = 1024;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    valid_proofs.push(blob.clone());
    da_service
        .send_transaction(DaTxRequest::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Sequencer commitment with wrong key and signature
    wrong_key_da_service
        .send_transaction(DaTxRequest::SequencerCommitment(SequencerCommitment {
            merkle_root: [15; 32],
            index: seq_index,
            l2_end_block_number: 1268,
        }))
        .await
        .expect("Failed to send transaction");

    let commitment = SequencerCommitment {
        merkle_root: [15; 32],
        index: seq_index,
        l2_end_block_number: 1268,
    };
    valid_commitments.push(commitment.clone());
    da_service
        .send_transaction(DaTxRequest::SequencerCommitment(commitment))
        .await
        .expect("Failed to send transaction");

    // Invoke chunked zk proof generation with 3 chunks
    let size = MAX_TX_BODY_SIZE * 2 + 2500;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    valid_proofs.push(blob.clone());
    da_service
        .send_transaction(DaTxRequest::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Send method id update tx
    let method_id = BatchProofMethodId {
        method_id: [1; 8],
        activation_l2_height: 100,
    };
    valid_method_ids.push(method_id.clone());
    da_service
        .send_transaction(DaTxRequest::BatchProofMethodId(method_id))
        .await
        .expect("Failed to send transaction");

    // Write all txs to a block
    let block_hash = da_node.generate(1).await.unwrap()[0];

    let block = da_service
        .get_block_by_hash(block_hash.into())
        .await
        .unwrap();
    assert_eq!(block.txdata.len(), 33);

    (block, valid_commitments, valid_proofs, valid_method_ids)
}

/// Used for generating big state diff
pub async fn create_deploy_transactions(
    block_count: usize,
    nonce: Option<u64>,
) -> (Vec<Vec<u8>>, u64) {
    // 11 tx fits into a single block
    let deploy_count: usize = block_count * 11;

    let bytecode_hex = fs::read_to_string("tests/bitcoin/test-data/big-contract.bin").unwrap();
    let bytecode_size = bytecode_hex.len() / 2;

    // extra 32 bytes for constructor argument
    let mut bytecode_with_args = vec![0; bytecode_size + 32];
    hex::decode_to_slice(bytecode_hex, &mut bytecode_with_args[0..bytecode_size]).unwrap();

    // prepare signer
    let private_key: [u8; 32] =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .unwrap()
            .try_into()
            .unwrap();
    let mut signer = PrivateKeySigner::from_slice(&private_key).unwrap();
    signer.set_chain_id(Some(5655));

    let mut nonce = nonce.unwrap_or(0);

    let mut signed_txs = Vec::with_capacity(deploy_count);
    for _ in 0..deploy_count {
        // set constructor argument different for each contract.
        // since constructor argument sets immutable storage variable
        // this will make bytecode of each contract different
        let rand_int = rand::random::<u32>();
        bytecode_with_args[bytecode_size..]
            .copy_from_slice(U256::from(rand_int).to_be_bytes::<32>().as_slice());

        let mut tx = TxLegacy {
            chain_id: Some(5655),
            nonce,
            gas_price: 1_000_000_000 * 1_000_000_000, // 1_000_000_000 gwei
            gas_limit: 3_000_000,                     // 3 million gas
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::copy_from_slice(&bytecode_with_args),
        };

        nonce += 1;

        let signature = signer.sign_transaction(&mut tx).await.unwrap();
        let signed_tx = tx.into_signed(signature);

        let mut rlp_buf = Vec::with_capacity(signed_tx.rlp_encoded_length());
        signed_tx.rlp_encode(&mut rlp_buf);

        signed_txs.push(rlp_buf);
    }

    (signed_txs, nonce)
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
