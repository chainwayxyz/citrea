use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_primitives::{B256, U64};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::bail;
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig};
use bitcoin_da::spec::RollupParams;
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_e2e::config::BitcoinConfig;
use citrea_e2e::node::{BatchProver, FullNode, NodeKind};
use citrea_primitives::REVEAL_TX_PREFIX;
use reth_tasks::TaskExecutor;
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::rpc::{JobRpcResponse, VerifiedBatchProofResponse};
use sov_rollup_interface::Network;
use tokio::time::sleep;
use uuid::Uuid;

pub(super) enum DaServiceKeyKind {
    #[allow(dead_code)]
    Sequencer,
    BatchProver,
    Other(String),
}

pub const BATCH_PROOF_METHOD_ID_UPDATE_AUTHORITY_TEST_PRIVATE_KEYS: [&str; 5] = [
    "79122E48DF1A002FB6584B2E94D0D50F95037416C82DAF280F21CD67D17D9077",
    "79122E48DF1A002FB6584B2E94D0D50F95037416C82DAF280F21CD67D17D9076",
    "79122E48DF1A002FB6584B2E94D0D50F95037416C82DAF280F21CD67D17D9075",
    "79122E48DF1A002FB6584B2E94D0D50F95037416C82DAF280F21CD67D17D9074",
    "79122E48DF1A002FB6584B2E94D0D50F95037416C82DAF280F21CD67D17D9073",
];

pub const SEQUENCER_DA_PUBLIC_KEY: &str =
    "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262";
pub(super) const PROVER_DA_PUBLIC_KEY: &str =
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

/// Converts a vector of signatures in Vec<u8> format to an array of signatures in [u8; 64] format
fn from_vec_to_sigs(vec: Vec<(Vec<u8>, u8)>) -> [([u8; 64], u8); 3] {
    let mut sigs = Vec::new();
    for (v, i) in vec.into_iter() {
        sigs.push((v.try_into().unwrap(), i));
    }
    sigs.try_into().unwrap()
}

/// Generates 5 valid keypairs and returns the public keys and signers from the given private keys
pub(crate) fn generate_initial_pub_keys_with_signers_from_pks(
    private_keys: [[u8; 32]; 5],
) -> ([[u8; 33]; 5], Vec<PrivateKeySigner>) {
    let mut initial_da_pubkeys = [[0u8; 33]; 5];
    let mut signers = Vec::new();

    // Generate 5 valid keypairs and signatures
    for (i, secret_key) in private_keys.iter().enumerate() {
        let signer = PrivateKeySigner::from_bytes(&secret_key.into()).unwrap();
        let verifying_key = signer.credential().verifying_key();
        let pubkey = verifying_key.to_sec1_bytes();
        initial_da_pubkeys[i] = pubkey.to_vec().try_into().unwrap();
        signers.push(signer);
    }

    (initial_da_pubkeys, signers)
}

/// Creates 3 valid signatures from the first 3 signers for the given prehash
pub(crate) fn create_valid_signatures(
    signers: &[PrivateKeySigner],
    prehash: &B256,
) -> [([u8; 64], u8); 3] {
    let mut signatures_in_inscription = Vec::new();

    for (i, signer) in signers.iter().enumerate().take(3) {
        let sig = signer.sign_hash_sync(prehash).unwrap();
        let signature = sig.as_bytes()[0..64].to_vec();
        signatures_in_inscription.push((signature, i as u8));
    }

    from_vec_to_sigs(signatures_in_inscription)
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
