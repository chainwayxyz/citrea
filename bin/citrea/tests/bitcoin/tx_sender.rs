use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use alloy_primitives::U64;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use bitcoincore_rpc::RpcApi;
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_batch_prover::PartitionMode;
use citrea_e2e::bitcoin::{BitcoinNode, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::config::{BatchProverConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::{FullNode, NodeKind, Sequencer};
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use citrea_light_client_prover::circuit::initial_values::bitcoinda::NIGHTLY_INITIAL_BATCH_PROOF_METHOD_IDS;
use citrea_primitives::compression::compress_blob;
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::rpc::SequencerCommitmentResponse;
use tx_sender_jsonrpc_client::{
    CitreaTxRequest, CommitRevealKind, CommitRevealStatus, JsonRpcTxSenderClient, TrackRequest,
    TrackResponse, TrackStatus,
};

use super::get_citrea_path;
use crate::bitcoin::light_client_test::{
    create_random_state_diff, create_serialized_fake_receipt_batch_proof,
};
use crate::bitcoin::sequencer_commitments::wait_for_sequencer_commitments;
use crate::bitcoin::utils::{
    wait_for_prover_job, wait_for_prover_job_count, wait_for_prover_job_with_l1_tx_id,
    wait_for_zkproofs,
};

async fn get_commit_reveal_status(
    client: &JsonRpcTxSenderClient,
    job_id: i64,
) -> Result<CommitRevealStatus> {
    match client
        .track_tx(TrackRequest::CommitReveal {
            insertion_id: job_id,
        })
        .await?
    {
        TrackResponse::CommitReveal(status) => Ok(status),
        TrackResponse::Transaction(_) => Err(anyhow::anyhow!(
            "expected CommitReveal response for insertion_id {job_id}"
        )),
    }
}

async fn wait_for_finalized_commit_reveal(
    client: &JsonRpcTxSenderClient,
    job_id: i64,
    timeout: Option<Duration>,
) -> Result<CommitRevealStatus> {
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(120));

    loop {
        let status = get_commit_reveal_status(client, job_id).await?;

        match status.status {
            TrackStatus::Finalized => return Ok(status),
            TrackStatus::Cancelled => {
                return Err(anyhow::anyhow!("tx-sender job {job_id} was cancelled"))
            }
            TrackStatus::Pending | TrackStatus::InProgress | TrackStatus::Mined => {}
        }

        if start.elapsed() >= timeout {
            return Err(anyhow::anyhow!(
                "timeout waiting for tx-sender job {job_id} to finalize"
            ));
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_for_commit_reveal_until<F>(
    client: &JsonRpcTxSenderClient,
    job_id: i64,
    timeout: Option<Duration>,
    mut predicate: F,
) -> Result<CommitRevealStatus>
where
    F: FnMut(&CommitRevealStatus) -> bool,
{
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(120));

    loop {
        let status = get_commit_reveal_status(client, job_id).await?;
        if predicate(&status) {
            return Ok(status);
        }

        if status.status == TrackStatus::Cancelled {
            return Err(anyhow::anyhow!("tx-sender job {job_id} was cancelled"));
        }

        if start.elapsed() >= timeout {
            return Err(anyhow::anyhow!(
                "timeout waiting for tx-sender job {job_id} to reach expected state"
            ));
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn collect_mined_heights(status: &CommitRevealStatus) -> BTreeSet<u32> {
    let mut heights = BTreeSet::new();

    if let Some(commit_tx) = &status.commit_tx {
        if let Some(height) = commit_tx.mined_at_height {
            heights.insert(height);
        }
    }

    for reveal in &status.reveals {
        if let Some(submission) = &reveal.submission {
            if let Some(height) = submission.tx_info.mined_at_height {
                heights.insert(height);
            }
        }
    }

    if let Some(aggregate_commit_tx) = &status.aggregate_commit_tx {
        if let Some(height) = aggregate_commit_tx.mined_at_height {
            heights.insert(height);
        }
    }

    heights
}

fn total_chunk_count(status: &CommitRevealStatus) -> usize {
    status
        .reveals
        .iter()
        .filter(|reveal| matches!(reveal.kind, CommitRevealKind::Chunk))
        .count()
}

fn submitted_chunk_count(status: &CommitRevealStatus) -> usize {
    status
        .reveals
        .iter()
        .filter(|reveal| {
            matches!(reveal.kind, CommitRevealKind::Chunk) && reveal.submission.is_some()
        })
        .count()
}

fn aggregate_reveal(
    status: &CommitRevealStatus,
) -> Option<&tx_sender_jsonrpc_client::RevealStatus> {
    status
        .reveals
        .iter()
        .find(|reveal| matches!(reveal.kind, CommitRevealKind::Aggregate))
}

fn aggregate_reveal_mined_height(status: &CommitRevealStatus) -> Option<u32> {
    aggregate_reveal(status)
        .and_then(|reveal| reveal.submission.as_ref())
        .and_then(|submission| submission.tx_info.mined_at_height)
}

fn get_reveal_txid(status: &CommitRevealStatus) -> Option<[u8; 32]> {
    status
        .aggregate_commit_tx
        .as_ref()
        .and_then(|aggregate_commit| aggregate_commit.txid.parse::<Txid>().ok())
        .or_else(|| {
            status
                .reveals
                .iter()
                .rev()
                .filter_map(|reveal| reveal.submission.as_ref())
                .find_map(|submission| submission.tx_info.txid.parse::<Txid>().ok())
        })
        .map(|txid| txid.to_byte_array())
}

fn sequencer_commitment_from_response(
    commitment_response: &SequencerCommitmentResponse,
) -> SequencerCommitment {
    SequencerCommitment {
        merkle_root: commitment_response.merkle_root,
        index: commitment_response.index.to::<u32>(),
        l2_end_block_number: commitment_response.l2_end_block_number.to::<u64>(),
    }
}

async fn publish_commitment_and_wait_for_commitments(
    sequencer: &Sequencer,
    da: &BitcoinNode,
    full_node: &FullNode,
    l2_height: u64,
) -> Result<(u64, Vec<SequencerCommitmentResponse>)> {
    let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

    for _ in 0..max_l2_blocks_per_commitment {
        sequencer.client.send_publish_batch_request().await?;
    }
    sequencer.wait_for_l2_height(l2_height, None).await?;

    // Wait for commitment tx to be submitted to DA
    da.wait_mempool_len(2, None).await?;

    // Finalize the DA block which contains the commitment tx
    da.generate(DEFAULT_FINALITY_DEPTH).await?;

    let finalized_height = da.get_finalized_height(None).await?;
    full_node.wait_for_l1_height(finalized_height, None).await?;
    let commitments = wait_for_sequencer_commitments(full_node, finalized_height, None).await?;

    Ok((finalized_height, commitments))
}

async fn create_large_batch_proof(
    da: &BitcoinNode,
    full_node: &FullNode,
    commitment_finalized_height: u64,
    commitment: &SequencerCommitment,
    state_diff_size_kb: u64,
) -> Result<Vec<u8>> {
    let genesis_state_root: [u8; 32] = full_node
        .client
        .http_client()
        .get_l2_genesis_state_root()
        .await?
        .unwrap()
        .0
        .try_into()
        .unwrap();
    let state_diff = create_random_state_diff(state_diff_size_kb);
    let commitment_l1_hash = da.get_block_hash(commitment_finalized_height).await?;

    Ok(create_serialized_fake_receipt_batch_proof(
        genesis_state_root,
        commitment.l2_end_block_number,
        NIGHTLY_INITIAL_BATCH_PROOF_METHOD_IDS.inner()[0].1,
        Some(state_diff),
        false,
        commitment_l1_hash.as_raw_hash().to_byte_array(),
        vec![commitment.clone()],
        None,
    ))
}

/// Basic test: sequencer routes commitments through the tx-sender service.
struct TxSenderBasicTest;

#[async_trait]
impl TestCase for TxSenderBasicTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let full_node = f.full_node.as_ref().unwrap();
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let (_, commitments) = publish_commitment_and_wait_for_commitments(
            sequencer,
            da,
            full_node,
            max_l2_blocks_per_commitment,
        )
        .await?;
        assert!(!commitments.is_empty(), "Expected at least one commitment");
        assert_eq!(
            commitments[0].l2_end_block_number.to::<u64>(),
            max_l2_blocks_per_commitment
        );

        Ok(())
    }
}

#[tokio::test]
async fn tx_sender_basic_test() -> Result<()> {
    TestCaseRunner::new(TxSenderBasicTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Restart test: sequencer reconnects to tx-sender after restart and continues
/// publishing commitments.
struct TxSenderRestartTest;

#[async_trait]
impl TestCase for TxSenderRestartTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_mut().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let full_node = f.full_node.as_ref().unwrap();
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let (_, commitments) = publish_commitment_and_wait_for_commitments(
            sequencer,
            da,
            full_node,
            max_l2_blocks_per_commitment,
        )
        .await?;
        assert!(!commitments.is_empty());

        sequencer.restart(None, None).await?;

        let (_, commitments) = publish_commitment_and_wait_for_commitments(
            sequencer,
            da,
            full_node,
            max_l2_blocks_per_commitment * 2,
        )
        .await?;
        assert!(!commitments.is_empty());

        Ok(())
    }
}

#[tokio::test]
async fn tx_sender_restart_test() -> Result<()> {
    TestCaseRunner::new(TxSenderRestartTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Batch prover routes proof submission through the tx-sender and ultimately stores
/// a real L1 txid (not all-zeros). This validates the full job-based DA flow:
///   send_transaction → tx-sender send_citrea_tx → wait_for_transaction_id →
///   track_tx → Finalized → finalize_proving_job stores the real txid.
struct TxSenderBatchProverTxidTest;

#[async_trait]
impl TestCase for TxSenderBatchProverTxidTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let tx_sender = f
            .tx_senders
            .get(&NodeKind::BatchProver)
            .expect("batch prover tx-sender not running");
        let tx_sender_client = JsonRpcTxSenderClient::new(&tx_sender.config.local_url())?;

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment * 2 {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment * 2, None)
            .await?;

        // Wait for commitment txs to be submitted to DA
        da.wait_mempool_len(4, None).await?;

        // Finalize the DA block which contains the commitment txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for batch prover to generate proof for commitment
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Ensure that batch proof is submitted to DA
        da.wait_mempool_len(2, None).await?;

        // Finalize the DA block which contains the batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_finalized_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(proof_finalized_height, None)
            .await?;

        // Wait for full node to see zkproofs
        let batch_proofs = wait_for_zkproofs(
            full_node,
            finalized_height + DEFAULT_FINALITY_DEPTH,
            None,
            1,
        )
        .await?;

        assert!(
            !batch_proofs.is_empty(),
            "Expected at least one batch proof"
        );

        // Wait for the proving job to be finalized with a real l1_tx_id.
        let job_ids = wait_for_prover_job_count(batch_prover, 1, None).await?;
        let response = wait_for_prover_job_with_l1_tx_id(batch_prover, job_ids[0], None).await?;

        let proof = response.proof.expect("Job should have a proof");
        let l1_tx_id = proof
            .l1_tx_id
            .expect("l1_tx_id should be set after DA finalization");

        assert_ne!(
            l1_tx_id, [0u8; 32],
            "l1_tx_id should be a real Bitcoin txid, not all-zeros"
        );

        let finalized_status = wait_for_finalized_commit_reveal(&tx_sender_client, 1, None).await?;
        let reveal_txid = get_reveal_txid(&finalized_status)
            .expect("finalized batch prover tx-sender job should expose a reveal txid");
        assert_eq!(
            l1_tx_id, reveal_txid,
            "batch prover should return the reveal or aggregate reveal txid"
        );

        Ok(())
    }
}

#[tokio::test]
async fn tx_sender_batch_prover_txid_test() -> Result<()> {
    TestCaseRunner::new(TxSenderBatchProverTxidTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// `submitFakeProof` is explicitly called out in the job-service issue.
/// This test verifies that the RPC still drives the
/// proof through the external tx-sender path and returns a real finalized L1 txid.
struct TxSenderSubmitFakeProofTest;

#[async_trait]
impl TestCase for TxSenderSubmitFakeProofTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            // prevent background proving from racing the explicit proof jobs under test
            proof_sampling_number: 999_999_999_999,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        // Finalize the first commitment and prove it so the fake proof for commitment 2
        // can be verified rather than kept in the pending pool.
        let (first_commitment_finalized_height, _) = publish_commitment_and_wait_for_commitments(
            sequencer,
            da,
            full_node,
            max_l2_blocks_per_commitment,
        )
        .await?;

        // Wait for batch prover to generate proof for commitment
        batch_prover
            .wait_for_l1_height(first_commitment_finalized_height, None)
            .await?;

        let first_job_id = batch_prover
            .client
            .http_client()
            .prove(PartitionMode::Normal)
            .await?[0];

        // Ensure that batch proof is submitted to DA
        da.wait_mempool_len(2, None).await?;

        // Finalize the DA block which contains the batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let first_proof_finalized_height = da.get_finalized_height(None).await?;
        let response = wait_for_prover_job(batch_prover, first_job_id, None).await?;

        full_node
            .wait_for_l1_height(first_proof_finalized_height, None)
            .await?;
        let batch_proofs =
            wait_for_zkproofs(full_node, first_proof_finalized_height, None, 1).await?;
        assert!(!batch_proofs.is_empty());
        assert!(response.proof.is_some());

        let (second_commitment_finalized_height, _) = publish_commitment_and_wait_for_commitments(
            sequencer,
            da,
            full_node,
            max_l2_blocks_per_commitment * 2,
        )
        .await?;

        // Wait for batch prover to generate proof for commitment
        batch_prover
            .wait_for_l1_height(second_commitment_finalized_height, None)
            .await?;

        let client = batch_prover.client.http_client().clone();
        let fake_proof_handle = tokio::spawn(async move { client.submit_fake_proof(2, 2).await });

        // Drive the tx-sender-backed DA submission to completion while the RPC waits.
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_finalized_height = da.get_finalized_height(None).await?;

        let fake_proof_response = fake_proof_handle.await.unwrap()?;

        assert!(fake_proof_response.info.is_none());
        let l1_tx_id = fake_proof_response
            .l1_tx_id
            .expect("submitFakeProof should return an l1_tx_id");
        assert_ne!(
            l1_tx_id, [0u8; 32],
            "submitFakeProof should return a real Bitcoin txid under tx-sender"
        );

        full_node
            .wait_for_l1_height(proof_finalized_height, None)
            .await?;
        let proofs = wait_for_zkproofs(full_node, proof_finalized_height, None, 1).await?;

        assert!(
            !proofs.is_empty(),
            "Expected fake proof to be visible on the full node"
        );
        assert_eq!(proofs[0].proof_output, fake_proof_response.proof_output);

        Ok(())
    }
}

#[tokio::test]
async fn tx_sender_submit_fake_proof_test() -> Result<()> {
    TestCaseRunner::new(TxSenderSubmitFakeProofTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Submits a valid oversized batch proof through tx-sender and verifies that:
/// 1. tx-sender spreads it across multiple Bitcoin blocks, and
/// 2. the full node ingests the finalized proof.
struct TxSenderLargeBatchProofChunkingTest;

#[async_trait]
impl TestCase for TxSenderLargeBatchProofChunkingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            // prevent background proving from racing the explicit proof job under test
            proof_sampling_number: 999_999_999_999,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let tx_sender = f
            .tx_senders
            .get(&NodeKind::BatchProver)
            .expect("batch prover tx-sender not running");
        let client = JsonRpcTxSenderClient::new(&tx_sender.config.local_url())?;
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let (commitment_finalized_height, commitments) =
            publish_commitment_and_wait_for_commitments(
                sequencer,
                da,
                full_node,
                max_l2_blocks_per_commitment,
            )
            .await?;
        let commitment = sequencer_commitment_from_response(&commitments[0]);
        let proof =
            create_large_batch_proof(da, full_node, commitment_finalized_height, &commitment, 450)
                .await?;

        let compressed_proof = compress_blob(&proof)?;
        assert!(
            compressed_proof.len() > 390 * 1024,
            "compressed proof must stay above tx-sender chunking threshold"
        );

        let job_id = client
            .send_citrea_tx(CitreaTxRequest::BatchProof {
                bytes: compressed_proof,
                chunk_size: None,
            })
            .await?;

        // Oversized proofs should start broadcasting, but the exact mempool occupancy is not
        // stable because Bitcoin Core can start rejecting descendants once the chain grows.
        // What matters for this issue is that tx-sender keeps the job alive and spreads the
        // proof across multiple mined Bitcoin blocks.
        da.wait_mempool_len(1, None).await?;

        let first_status = get_commit_reveal_status(&client, job_id).await?;
        assert!(matches!(
            first_status.status,
            TrackStatus::Pending | TrackStatus::InProgress | TrackStatus::Mined
        ));

        let mut mined_rounds = 0;
        loop {
            da.generate(1).await?;
            mined_rounds += 1;

            let status = get_commit_reveal_status(&client, job_id).await?;
            match status.status {
                TrackStatus::Finalized | TrackStatus::Mined => break,
                TrackStatus::Cancelled => {
                    return Err(anyhow::anyhow!("tx-sender job {job_id} was cancelled"))
                }
                TrackStatus::Pending | TrackStatus::InProgress => {
                    da.wait_mempool_len(1, None).await?;
                }
            }

            if mined_rounds >= 8 {
                return Err(anyhow::anyhow!(
                    "oversized tx-sender proof job {job_id} did not finish mining after {mined_rounds} blocks"
                ));
            }
        }

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_finalized_height = da.get_finalized_height(None).await?;

        let finalized_status = wait_for_finalized_commit_reveal(&client, job_id, None).await?;
        let mined_heights = collect_mined_heights(&finalized_status);

        assert_eq!(finalized_status.status, TrackStatus::Finalized);
        assert!(finalized_status.reveals.len() > 1);
        assert!(finalized_status
            .reveals
            .iter()
            .any(|reveal| matches!(reveal.kind, CommitRevealKind::Chunk)));
        assert!(finalized_status.aggregate_commit_tx.is_some());
        assert!(mined_heights.len() >= 2);

        // The full node indexes proofs by the L1 height of the aggregate reveal tx,
        // not by `proof_finalized_height` (which is tip - finality_depth + 1).
        let proof_l1_height = u64::from(
            aggregate_reveal_mined_height(&finalized_status)
                .expect("finalized chunked proof should have an aggregate reveal mined height"),
        );
        full_node
            .wait_for_l1_height(proof_finalized_height, None)
            .await?;
        let proofs = wait_for_zkproofs(full_node, proof_l1_height, None, 1).await?;
        let proof = proofs
            .iter()
            .find(|proof| {
                proof
                    .proof_output
                    .sequencer_commitment_index_range
                    .0
                    .to::<u32>()
                    == commitment.index
                    && proof
                        .proof_output
                        .sequencer_commitment_index_range
                        .1
                        .to::<u32>()
                        == commitment.index
            })
            .expect("expected chunked proof for the submitted commitment");
        assert_eq!(
            proof
                .proof_output
                .sequencer_commitment_index_range
                .0
                .to::<u32>(),
            commitment.index
        );
        assert_eq!(
            proof
                .proof_output
                .sequencer_commitment_index_range
                .1
                .to::<u32>(),
            commitment.index
        );

        Ok(())
    }
}

#[tokio::test]
async fn tx_sender_large_batch_proof_chunking_test() -> Result<()> {
    TestCaseRunner::new(TxSenderLargeBatchProofChunkingTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Reorgs a chunked tx-sender proof before finality, verifies `track_tx` moves back to
/// `InProgress`, then verifies the job re-mines and finalizes successfully.
struct TxSenderLargeBatchProofReorgRebroadcastTest;

#[async_trait]
impl TestCase for TxSenderLargeBatchProofReorgRebroadcastTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let tx_sender = f
            .tx_senders
            .get(&NodeKind::Sequencer)
            .expect("sequencer tx-sender not running");
        let client = JsonRpcTxSenderClient::new(&tx_sender.config.local_url())?;
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let (commitment_finalized_height, commitments) =
            publish_commitment_and_wait_for_commitments(
                sequencer,
                da,
                full_node,
                max_l2_blocks_per_commitment,
            )
            .await?;
        let commitment = sequencer_commitment_from_response(&commitments[0]);
        let proof =
            create_large_batch_proof(da, full_node, commitment_finalized_height, &commitment, 450)
                .await?;

        let compressed_proof = compress_blob(&proof)?;
        assert!(
            compressed_proof.len() > 390 * 1024,
            "compressed proof must stay above tx-sender chunking threshold"
        );

        let job_id = client
            .send_citrea_tx(CitreaTxRequest::BatchProof {
                bytes: compressed_proof,
                chunk_size: None,
            })
            .await?;

        da.wait_mempool_len(1, None).await?;

        let initial_mined_status = loop {
            da.generate(1).await?;

            let status = get_commit_reveal_status(&client, job_id).await?;
            match status.status {
                TrackStatus::Mined => break status,
                TrackStatus::Pending | TrackStatus::InProgress => {
                    da.wait_mempool_len(1, None).await?;
                }
                TrackStatus::Finalized => {
                    return Err(anyhow::anyhow!(
                        "tx-sender job {job_id} finalized before the reorg step"
                    ));
                }
                TrackStatus::Cancelled => {
                    return Err(anyhow::anyhow!("tx-sender job {job_id} was cancelled"));
                }
            }
        };

        let initial_mined_heights = collect_mined_heights(&initial_mined_status);
        assert!(
            initial_mined_heights.len() >= 2,
            "expected chunked proof to occupy multiple mined Bitcoin blocks before reorg"
        );
        let rollback_height = u64::from(
            *initial_mined_heights
                .iter()
                .next()
                .expect("mined proof height must exist"),
        );
        let rollback_hash = da.get_block_hash(rollback_height).await?;
        da.invalidate_block(&rollback_hash).await?;

        let reorged_status = wait_for_commit_reveal_until(&client, job_id, None, |status| {
            status.status == TrackStatus::InProgress
        })
        .await?;
        assert!(
            collect_mined_heights(&reorged_status).is_empty(),
            "reorged proof job should no longer expose mined heights"
        );

        let resumed_mined_status = loop {
            if !da.get_raw_mempool().await?.is_empty() {
                da.generate(1).await?;
            } else {
                da.wait_mempool_len(1, None).await?;
                continue;
            }

            let status = get_commit_reveal_status(&client, job_id).await?;
            match status.status {
                TrackStatus::Mined => break status,
                TrackStatus::Pending | TrackStatus::InProgress => {}
                TrackStatus::Finalized => break status,
                TrackStatus::Cancelled => {
                    return Err(anyhow::anyhow!("tx-sender job {job_id} was cancelled"));
                }
            }
        };
        let resumed_mined_heights = collect_mined_heights(&resumed_mined_status);
        assert!(
            !resumed_mined_heights.is_empty(),
            "proof job should mine again after the reorg"
        );

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_status = wait_for_finalized_commit_reveal(&client, job_id, None).await?;
        let finalized_mined_heights = collect_mined_heights(&finalized_status);

        assert_eq!(finalized_status.status, TrackStatus::Finalized);
        assert!(finalized_status.reveals.len() > 1);
        assert!(finalized_status
            .reveals
            .iter()
            .any(|reveal| matches!(reveal.kind, CommitRevealKind::Chunk)));
        assert!(finalized_status.aggregate_commit_tx.is_some());
        assert!(
            !finalized_mined_heights.is_empty(),
            "finalized proof job should retain mined tx information after rebroadcast"
        );

        Ok(())
    }
}

#[tokio::test]
async fn tx_sender_large_batch_proof_reorg_rebroadcast_test() -> Result<()> {
    TestCaseRunner::new(TxSenderLargeBatchProofReorgRebroadcastTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Restarts tx-sender while an oversized proof job is only partially submitted,
/// verifies the job is restored from persistent state, then verifies it continues
/// mining and finalizes successfully.
struct TxSenderLargeBatchProofRestartRecoveryTest;

#[async_trait]
impl TestCase for TxSenderLargeBatchProofRestartRecoveryTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            // prevent background proving from racing the explicit proof job under test
            proof_sampling_number: 999_999_999_999,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let (commitment_finalized_height, commitments) =
            publish_commitment_and_wait_for_commitments(
                sequencer,
                da,
                full_node,
                max_l2_blocks_per_commitment,
            )
            .await?;
        let commitment = sequencer_commitment_from_response(&commitments[0]);
        let proof =
            create_large_batch_proof(da, full_node, commitment_finalized_height, &commitment, 450)
                .await?;

        let compressed_proof = compress_blob(&proof)?;
        assert!(
            compressed_proof.len() > 390 * 1024,
            "compressed proof must stay above tx-sender chunking threshold"
        );

        let initial_client = {
            let tx_sender = f
                .tx_senders
                .get(&NodeKind::BatchProver)
                .expect("batch prover tx-sender not running");
            JsonRpcTxSenderClient::new(&tx_sender.config.local_url())?
        };
        let job_id = initial_client
            .send_citrea_tx(CitreaTxRequest::BatchProof {
                bytes: compressed_proof,
                chunk_size: None,
            })
            .await?;

        da.wait_mempool_len(1, None).await?;

        let partial_status =
            wait_for_commit_reveal_until(&initial_client, job_id, None, |status| {
                total_chunk_count(status) >= 2
                    && matches!(status.status, TrackStatus::InProgress | TrackStatus::Mined)
                    && status.status != TrackStatus::Finalized
            })
            .await?;
        let total_chunks_before_restart = total_chunk_count(&partial_status);
        assert!(
            matches!(
                partial_status.status,
                TrackStatus::InProgress | TrackStatus::Mined
            ),
            "expected proof job to remain recoverable before tx-sender restart"
        );

        let restarted_client = {
            let tx_sender = f
                .tx_senders
                .get_mut(&NodeKind::BatchProver)
                .expect("batch prover tx-sender not running");
            tx_sender.restart(None, None).await?;
            JsonRpcTxSenderClient::new(&tx_sender.config.local_url())?
        };

        let recovered_status = get_commit_reveal_status(&restarted_client, job_id).await?;
        assert!(
            recovered_status.status != TrackStatus::Cancelled,
            "restarted tx-sender should keep the persisted proof job alive"
        );
        assert!(
            total_chunk_count(&recovered_status) > 0,
            "restarted tx-sender should restore a chunked proof job for the same insertion_id"
        );
        assert!(
            total_chunk_count(&recovered_status) >= total_chunks_before_restart
                || matches!(
                    recovered_status.status,
                    TrackStatus::InProgress | TrackStatus::Mined
                )
                || recovered_status.commit_tx.is_some(),
            "restarted tx-sender should expose persisted progress for the recovered proof job"
        );

        let restart_recovery_timeout = Duration::from_secs(240);
        let mining_start = Instant::now();
        let mut mined_blocks = 0;
        let aggregate_mined_status = loop {
            let status = get_commit_reveal_status(&restarted_client, job_id).await?;
            if aggregate_reveal_mined_height(&status).is_some() {
                break status;
            }

            if status.status == TrackStatus::Cancelled {
                return Err(anyhow::anyhow!("tx-sender job {job_id} was cancelled"));
            }

            if mining_start.elapsed() >= restart_recovery_timeout {
                return Err(anyhow::anyhow!(
                    "restarted tx-sender proof job {job_id} did not mine the aggregate reveal within {:?} after {mined_blocks} mined blocks",
                    restart_recovery_timeout
                ));
            }

            if da.get_raw_mempool().await?.is_empty() {
                da.wait_mempool_len(1, Some(restart_recovery_timeout))
                    .await?;
                continue;
            }

            da.generate(1).await?;
            mined_blocks += 1;
        };
        assert!(
            !collect_mined_heights(&aggregate_mined_status).is_empty(),
            "restarted proof job should mine after tx-sender comes back up"
        );
        let aggregate_mined_height = aggregate_reveal_mined_height(&aggregate_mined_status)
            .expect("aggregate reveal should be mined before finality is checked");

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_finalized_height = da.get_finalized_height(None).await?;

        let finalized_status = wait_for_finalized_commit_reveal(
            &restarted_client,
            job_id,
            Some(restart_recovery_timeout),
        )
        .await?;
        let finalized_aggregate_reveal = aggregate_reveal(&finalized_status)
            .expect("finalized proof job should expose aggregate reveal state");
        let finalized_aggregate_submission = finalized_aggregate_reveal
            .submission
            .as_ref()
            .expect("finalized proof job should retain aggregate reveal submission");
        assert_eq!(finalized_status.status, TrackStatus::Finalized);
        assert!(finalized_status.reveals.len() > 1);
        assert!(finalized_status
            .reveals
            .iter()
            .any(|reveal| matches!(reveal.kind, CommitRevealKind::Chunk)));
        assert!(finalized_status.aggregate_commit_tx.is_some());
        assert_eq!(
            finalized_aggregate_submission.status,
            TrackStatus::Finalized
        );
        assert_eq!(
            finalized_aggregate_submission.tx_info.mined_at_height,
            Some(aggregate_mined_height)
        );

        {
            // The proof is stored at the L1 height of the aggregate reveal, not at
            // `proof_finalized_height` (which is tip - finality_depth + 1 and may
            // overshoot by one block).
            let proof_l1_height = u64::from(aggregate_mined_height);
            full_node
                .wait_for_l1_height(proof_finalized_height, None)
                .await?;
            let proofs = wait_for_zkproofs(full_node, proof_l1_height, None, 1).await?;
            let proof = proofs
                .iter()
                .find(|proof| {
                    proof
                        .proof_output
                        .sequencer_commitment_index_range
                        .0
                        .to::<u32>()
                        == commitment.index
                        && proof
                            .proof_output
                            .sequencer_commitment_index_range
                            .1
                            .to::<u32>()
                            == commitment.index
                })
                .expect("expected recovered chunked proof for the submitted commitment");
            assert_eq!(
                proof
                    .proof_output
                    .sequencer_commitment_index_range
                    .0
                    .to::<u32>(),
                commitment.index
            );
            assert_eq!(
                proof
                    .proof_output
                    .sequencer_commitment_index_range
                    .1
                    .to::<u32>(),
                commitment.index
            );
        }

        Ok(())
    }
}

#[tokio::test]
async fn tx_sender_large_batch_proof_restart_recovery_test() -> Result<()> {
    TestCaseRunner::new(TxSenderLargeBatchProofRestartRecoveryTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Tx-sender equivalent of the old `package-mempool-limits` queue test:
/// four default-chunked large proofs are submitted, the fourth cannot complete while earlier
/// work occupies mempool chain space, and it only advances after the next block is mined.
struct TxSenderPackageMempoolLimitsTest;

#[async_trait]
impl TestCase for TxSenderPackageMempoolLimitsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            // prevent background proving from racing the explicit proof jobs under test
            proof_sampling_number: 999_999_999_999,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let tx_sender = f
            .tx_senders
            .get(&NodeKind::BatchProver)
            .expect("batch prover tx-sender not running");
        let client = JsonRpcTxSenderClient::new(&tx_sender.config.local_url())?;
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let (commitment_finalized_height, commitments) =
            publish_commitment_and_wait_for_commitments(
                sequencer,
                da,
                full_node,
                max_l2_blocks_per_commitment,
            )
            .await?;
        let commitment = sequencer_commitment_from_response(&commitments[0]);

        let mut job_ids = Vec::with_capacity(4);
        for _ in 0..4 {
            let proof = create_large_batch_proof(
                da,
                full_node,
                commitment_finalized_height,
                &commitment,
                420,
            )
            .await?;
            let compressed_proof = compress_blob(&proof)?;
            assert!(
                compressed_proof.len() > 390_000,
                "proof should exceed tx-sender's default chunking threshold"
            );

            let job_id = client
                .send_citrea_tx(CitreaTxRequest::BatchProof {
                    bytes: compressed_proof,
                    chunk_size: None,
                })
                .await?;
            job_ids.push(job_id);
        }
        let all_job_ids = job_ids.clone();

        da.wait_mempool_len(1, None).await?;

        let start = Instant::now();
        let fourth_queued_or_partial_status = loop {
            let mut statuses = Vec::with_capacity(job_ids.len());
            for job_id in &job_ids {
                statuses.push(get_commit_reveal_status(&client, *job_id).await?);
            }

            let first_three_started = statuses[..3]
                .iter()
                .all(|status| !matches!(status.status, TrackStatus::Pending));
            let fourth_status = &statuses[3];
            let fourth_total = total_chunk_count(fourth_status);
            let fourth_submitted = submitted_chunk_count(fourth_status);
            if first_three_started && fourth_total >= 2 && fourth_submitted < fourth_total {
                break fourth_status.clone();
            }

            if start.elapsed() >= Duration::from_secs(120) {
                return Err(anyhow::anyhow!(
                    "timeout waiting for fourth tx-sender proof job to remain queued or partially started under mempool pressure"
                ));
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        };

        let fourth_partial_chunks = submitted_chunk_count(&fourth_queued_or_partial_status);
        let fourth_initial_status = fourth_queued_or_partial_status.status;
        assert!(
            fourth_partial_chunks < total_chunk_count(&fourth_queued_or_partial_status),
            "expected the fourth proof to still have unsent chunk work before mining"
        );

        da.generate(1).await?;

        let start = Instant::now();
        loop {
            let fourth_status = get_commit_reveal_status(&client, job_ids[3]).await?;
            let status_advanced = matches!(fourth_initial_status, TrackStatus::Pending)
                && !matches!(fourth_status.status, TrackStatus::Pending);
            let chunk_progressed = submitted_chunk_count(&fourth_status) > fourth_partial_chunks;
            if status_advanced || chunk_progressed || fourth_status.status == TrackStatus::Finalized
            {
                break;
            }

            if start.elapsed() >= Duration::from_secs(120) {
                return Err(anyhow::anyhow!(
                    "timeout waiting for the fourth tx-sender proof job to advance after mining the next block"
                ));
            }

            if da.get_raw_mempool().await?.is_empty() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            } else {
                da.wait_mempool_len(1, None).await?;
            }
        }

        let mining_start = Instant::now();
        let mut mined_blocks = 1;
        while !job_ids.is_empty() {
            let mut remaining = Vec::new();
            for job_id in &job_ids {
                let status = get_commit_reveal_status(&client, *job_id).await?;
                match status.status {
                    TrackStatus::Finalized | TrackStatus::Mined => {}
                    TrackStatus::Cancelled => {
                        return Err(anyhow::anyhow!("tx-sender job {job_id} was cancelled"))
                    }
                    TrackStatus::Pending | TrackStatus::InProgress => remaining.push(*job_id),
                }
            }

            if remaining.is_empty() {
                break;
            }

            da.generate(1).await?;
            mined_blocks += 1;
            if mining_start.elapsed() >= Duration::from_secs(120) {
                return Err(anyhow::anyhow!(
                    "proof jobs did not finish mining within {:?} after {mined_blocks} blocks",
                    Duration::from_secs(120)
                ));
            }
            job_ids = remaining;
        }

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        for job_id in all_job_ids {
            let finalized = wait_for_finalized_commit_reveal(&client, job_id, None).await?;
            assert_eq!(finalized.status, TrackStatus::Finalized);
        }

        Ok(())
    }
}

#[tokio::test]
async fn tx_sender_package_mempool_limits_test() -> Result<()> {
    TestCaseRunner::new(TxSenderPackageMempoolLimitsTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Sequencer publishes multiple rounds of commitments through the tx-sender,
/// verifying the poller completes each round and commitments are finalized on L1.
struct TxSenderMultipleCommitmentsTest;

#[async_trait]
impl TestCase for TxSenderMultipleCommitmentsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(150)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let full_node = f.full_node.as_ref().unwrap();
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let (finalized_height_1, commitments_1) = publish_commitment_and_wait_for_commitments(
            sequencer,
            da,
            full_node,
            max_l2_blocks_per_commitment,
        )
        .await?;
        assert_eq!(commitments_1.len(), 1);
        assert_eq!(
            commitments_1[0].l2_end_block_number.to::<u64>(),
            max_l2_blocks_per_commitment
        );

        let (finalized_height_2, commitments_2) = publish_commitment_and_wait_for_commitments(
            sequencer,
            da,
            full_node,
            max_l2_blocks_per_commitment * 2,
        )
        .await?;
        assert_eq!(commitments_2.len(), 1);
        assert_eq!(
            commitments_2[0].l2_end_block_number.to::<u64>(),
            max_l2_blocks_per_commitment * 2
        );

        let (finalized_height_3, commitments_3) = publish_commitment_and_wait_for_commitments(
            sequencer,
            da,
            full_node,
            max_l2_blocks_per_commitment * 3,
        )
        .await?;
        assert_eq!(commitments_3.len(), 1);
        assert_eq!(
            commitments_3[0].l2_end_block_number.to::<u64>(),
            max_l2_blocks_per_commitment * 3
        );

        // Verify commitment indices are sequential
        let c1 = full_node
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(U64::from(finalized_height_1))
            .await?
            .unwrap();
        let c2 = full_node
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(U64::from(finalized_height_2))
            .await?
            .unwrap();
        let c3 = full_node
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(U64::from(finalized_height_3))
            .await?
            .unwrap();

        assert_eq!(c1[0].index.to::<u32>() + 1, c2[0].index.to::<u32>());
        assert_eq!(c2[0].index.to::<u32>() + 1, c3[0].index.to::<u32>());

        Ok(())
    }
}

#[tokio::test]
async fn tx_sender_multiple_commitments_test() -> Result<()> {
    TestCaseRunner::new(TxSenderMultipleCommitmentsTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
