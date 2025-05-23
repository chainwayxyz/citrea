use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_primitives::U64;
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
