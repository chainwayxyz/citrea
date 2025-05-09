use std::collections::{hash_map, HashMap, VecDeque};
use std::sync::Arc;

use anyhow::Context;
use citrea_common::utils::merge_state_diffs;
use citrea_common::{BatchProverConfig, ProverGuestRunConfig};
use citrea_primitives::compression::compress_blob;
use citrea_primitives::forks::fork_from_block_number;
use citrea_primitives::MAX_TXBODY_SIZE;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use prover_services::{ParallelProverService, ProofData};
use rand::Rng;
use reth_tasks::shutdown::GracefulShutdown;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use short_header_proof_provider::SHORT_HEADER_PROOF_PROVIDER;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::L2BlockNumber;
use sov_keys::default_signature::K256PublicKey;
use sov_modules_api::{L2Block, SpecId, StateDiff, Zkvm};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::batch_proof::input::v3::BatchProofCircuitInputV3;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;
use sov_rollup_interface::zk::{Proof, ProofWithJob, ReceiptType, ZkvmHost};
use sov_state::Witness;
use tokio::select;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, instrument, warn};
use tracing_subscriber::layer::SubscriberExt;
use uuid::Uuid;

use crate::partition::{Partition, PartitionMode, PartitionReason, PartitionState};

pub enum ProverRequest {
    Pause,
    Prove(PartitionMode, oneshot::Sender<Vec<Uuid>>),
    CreateInput(
        PartitionMode,
        Vec<SequencerCommitment>,
        oneshot::Sender<Vec<Vec<u8>>>,
    ),
}

pub struct Prover<Da, DB, Vm>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + 'static,
    Vm: ZkvmHost + 'static,
{
    prover_config: BatchProverConfig,
    ledger_db: DB,
    storage_manager: ProverStorageManager,
    prover_service: Arc<ParallelProverService<Da, Vm>>,
    sequencer_pub_key: K256PublicKey,
    elfs_by_spec: HashMap<SpecId, Vec<u8>>,
    code_commitments_by_spec: HashMap<SpecId, <Vm as Zkvm>::CodeCommitment>,
    l1_signal_rx: mpsc::Receiver<()>,
    l2_block_rx: broadcast::Receiver<u64>,
    request_rx: mpsc::Receiver<ProverRequest>,
    sync_target_l2_height: Option<u64>,
    proving_paused: bool,
}

impl<Da, DB, Vm> Prover<Da, DB, Vm>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone,
    Vm: ZkvmHost,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prover_config: BatchProverConfig,
        ledger_db: DB,
        storage_manager: ProverStorageManager,
        prover_service: Arc<ParallelProverService<Da, Vm>>,
        sequencer_pub_key: Vec<u8>,
        elfs_by_spec: HashMap<SpecId, Vec<u8>>,
        code_commitments_by_spec: HashMap<SpecId, <Vm as Zkvm>::CodeCommitment>,
        l1_signal_rx: mpsc::Receiver<()>,
        l2_block_rx: broadcast::Receiver<u64>,
        request_rx: mpsc::Receiver<ProverRequest>,
    ) -> Self {
        Self {
            prover_config,
            ledger_db,
            storage_manager,
            prover_service,
            sequencer_pub_key: K256PublicKey::try_from(sequencer_pub_key.as_slice())
                .expect("Invalid sequencer public key"),
            elfs_by_spec,
            code_commitments_by_spec,
            l1_signal_rx,
            l2_block_rx,
            request_rx,
            sync_target_l2_height: None,
            proving_paused: false,
        }
    }

    pub async fn run(mut self, mut shutdown_signal: GracefulShutdown) {
        self.recover_proving_sessions().await;

        'run_loop: loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    info!("Shutting down Prover");
                    return;
                }
                l1_signal = self.l1_signal_rx.recv() => {
                    l1_signal.expect("L1 signal sender channel closed abruptly");

                    debug!("Got L1 signal to try proving");
                    if let Err(e) = self.try_proving(PartitionMode::Normal, true).await {
                        error!("Failed to start proving: {}", e);
                    }
                },
                l2_signal = self.l2_block_rx.recv() => {
                    let l2_height = match l2_signal {
                        Ok(l2_height) => l2_height,
                        // prover will get the latest block number eventually
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        _ => panic!("L2 signal sender channel closed abruptly"),
                    };

                    let Some(sync_target_l2_height) = self.sync_target_l2_height else {
                        // we are already fully synced or no commitments are waiting for l2 blocks
                        continue;
                    };

                    if l2_height < sync_target_l2_height {
                        // new l2 height has not yet reached the next sync target
                        continue;
                    }

                    debug!("Got L2 signal to try proving");
                    if let Err(e) = self.try_proving(PartitionMode::Normal, true).await {
                        error!("Failed to start proving: {}", e);
                    }
                }
                request = self.request_rx.recv() => {
                    let request = request.expect("Rpc request channel closed abruptly");

                    match request {
                        ProverRequest::Pause => {
                            self.proving_paused = true;
                            warn!("Paused proving");
                        }
                        ProverRequest::Prove(mode, result_tx) => {
                            debug!("Got rpc request to try proving");
                            match self.try_proving(mode, false).await {
                                Ok(job_ids) => {
                                    let _ = result_tx.send(job_ids);
                                }
                                Err(e) => error!("Failed to handle prove request: {}", e),
                            }
                        }
                        ProverRequest::CreateInput(mode, mut commitments, result_tx) => {
                            let partitions = match self.create_partitions(&mut commitments, mode) {
                                Ok(partitions) => partitions,
                                Err(e) => {
                                    error!("Failed to create partitions based on rpc request: {}", e);
                                    continue;
                                }
                            };

                            let mut raw_inputs = Vec::with_capacity(partitions.len());
                            for partition in partitions {
                                match self.create_circuit_input(&partition) {
                                    Ok(input) => {
                                        let raw_input = borsh::to_vec(&input.into_v3_parts()).expect("Input serialization cannot fail");
                                        raw_inputs.push(raw_input);
                                    }
                                    Err(e) => {
                                        error!("Failed to create input from partition based on rpc request: {}", e);
                                        continue 'run_loop;
                                    }
                                }
                            }

                            let _ = result_tx.send(raw_inputs);
                        }
                    }
                }
            }
        }
    }

    async fn try_proving(
        &mut self,
        mode: PartitionMode,
        with_sampling: bool,
    ) -> anyhow::Result<Vec<Uuid>> {
        if self.proving_paused {
            debug!("Proving is paused");
            return Ok(Vec::new());
        }

        if with_sampling && !self.should_prove() {
            debug!("Skipping proving due to sampling");
            return Ok(Vec::new());
        }

        let mut commitments = self.ledger_db.get_prover_pending_commitments()?;
        if commitments.is_empty() {
            debug!("No pending commitments found");
            return Ok(Vec::new());
        }
        info!("Got {} pending commitment(s)", commitments.len());

        let partitions = self.create_partitions(&mut commitments, mode)?;
        if partitions.is_empty() {
            debug!("No provable commitments found");
            return Ok(vec![]);
        }

        let mut proving_jobs = Vec::with_capacity(partitions.len());
        for partition in partitions {
            let input = self
                .create_circuit_input(&partition)
                .context("Failed to create circuit input")?;

            let (id, rx) = self.start_proving(input).await?;
            proving_jobs.push((id, rx));

            let commitment_indices = partition
                .commitments
                .iter()
                .map(|comm| comm.index)
                .collect::<Vec<_>>();

            self.ledger_db
                .insert_new_proving_job(id, &commitment_indices)
                .context("Failed to insert prover job")?;
            self.ledger_db
                .delete_prover_pending_commitments(commitment_indices)
                .context("Failed to delete pending commitments")?;
        }

        let job_ids = proving_jobs.iter().map(|job| job.0).collect();

        self.watch_proving_jobs(proving_jobs);

        Ok(job_ids)
    }

    fn create_partitions<'a>(
        &mut self,
        commitments: &'a mut Vec<SequencerCommitment>,
        mode: PartitionMode,
    ) -> anyhow::Result<Vec<Partition<'a>>> {
        let filtered_commitments = self.filter_unsynced_commitments(commitments.clone())?;
        if filtered_commitments.is_empty() {
            warn!("L2 blocks not synced up to any of the pending commitments yet");
            return Ok(Vec::new());
        }
        info!("Got {} synced commitment(s)", filtered_commitments.len());

        let filtered_commitments = self.filter_prev_missing_commitments(filtered_commitments)?;
        if filtered_commitments.is_empty() {
            warn!("None of the pending commitments have a known previous commitment");
            return Ok(Vec::new());
        }
        info!("Got {} provable commitment(s)", filtered_commitments.len());

        *commitments = filtered_commitments;

        let partitions = self.partition_commitments(commitments, mode)?;
        info!("Partitioned commitments into {} parts", partitions.len());

        Ok(partitions)
    }

    /// Filters out the commitments that prover l2 blocks not synced to yet
    fn filter_unsynced_commitments(
        &mut self,
        mut commitments: Vec<SequencerCommitment>,
    ) -> anyhow::Result<Vec<SequencerCommitment>> {
        let head_l2_height = self.ledger_db.get_head_l2_block_height()?.unwrap_or(0);
        let l2_end_block_number = commitments
            .last()
            .expect("Commitments must not be empty")
            .l2_end_block_number;

        if l2_end_block_number <= head_l2_height {
            // short circuit for fully synced case
            self.sync_target_l2_height = None;
            return Ok(commitments);
        }

        // find first commitment position that is not synced
        let unsynced_pos = commitments
            .iter()
            .position(|comm| comm.l2_end_block_number > head_l2_height)
            .expect("Just ensured that at least one commitment is not synced");

        let sync_target_l2_height = commitments[unsynced_pos].l2_end_block_number;
        self.sync_target_l2_height = Some(sync_target_l2_height);

        let unsynced_count = commitments.drain(unsynced_pos..).count();

        warn!(
            "Only synced up to height {}, ignoring {} commitments, next sync target height is {}",
            head_l2_height, unsynced_count, sync_target_l2_height
        );

        Ok(commitments)
    }

    /// Filters out the commitments that doesn't have a known previous commitment, hence, can't be proven.
    /// E.g. commitments = [3, 4, 5], but commitment 2 is not known yet, outputs [4, 5]
    fn filter_prev_missing_commitments(
        &self,
        commitments: Vec<SequencerCommitment>,
    ) -> anyhow::Result<Vec<SequencerCommitment>> {
        commitments
            .into_iter()
            .filter_map(|comm| {
                if comm.index == 1 {
                    return Some(Ok(comm));
                }

                match self.ledger_db.get_commitment_by_index(comm.index - 1) {
                    // prev commitment exists
                    Ok(Some(_)) => Some(Ok(comm)),
                    // prev commitment doesn't exist
                    Ok(None) => None,
                    // db error
                    Err(e) => Some(Err(e)),
                }
            })
            .collect()
    }

    /// Partition the commitments into provable chunks. Here are the rules when partitioning in Normal mode:
    /// 1. If there is an index gap in between commitments, partition is formed
    /// 2. If ƒork has changed, partition is formed
    /// 3. If max state diff limit is surpassed, partition is formed
    ///
    /// This function expects each commitment to have previous commitment, so, ensure filtering commitments
    /// with `filter_prev_missing_commitments` before calling this function.
    fn partition_commitments<'a>(
        &self,
        commitments: &'a [SequencerCommitment],
        mode: PartitionMode,
    ) -> anyhow::Result<Vec<Partition<'a>>> {
        let mut state = PartitionState::new(commitments, self.ledger_db.clone())?;

        if mode == PartitionMode::OneByOne {
            for i in 0..commitments.len() {
                state.add_partition(i, PartitionReason::OneByOne)?;
            }
            return Ok(state.into_inner());
        }

        // Normal partition mode

        let mut cumulative_state_diff = StateDiff::new();
        let mut commitment_start_height = state.next_partition_start_height();

        for (i, commitment) in commitments.iter().enumerate() {
            let commitment_end_height = commitment.l2_end_block_number;

            let commitment_state_diff =
                self.get_state_diff(commitment_start_height, commitment_end_height)?;

            commitment_start_height = commitment_end_height + 1;

            // if first commitment, no need to check any condition
            if i == 0 {
                cumulative_state_diff = commitment_state_diff;
                continue;
            }

            // check index gap
            if commitment.index != commitments[i - 1].index + 1 {
                cumulative_state_diff = commitment_state_diff;
                state.add_partition(i - 1, PartitionReason::IndexGap)?;
                // override commitment start height as we lost track of the latest commitment due to index gap
                commitment_start_height = state.next_partition_start_height();
                continue;
            }

            // check spec change
            let current_spec = fork_from_block_number(commitment_end_height);
            if current_spec != fork_from_block_number(commitments[i - 1].l2_end_block_number) {
                cumulative_state_diff = commitment_state_diff;
                state.add_partition(i - 1, PartitionReason::SpecChange)?;
                continue;
            }

            cumulative_state_diff =
                merge_state_diffs(cumulative_state_diff, commitment_state_diff.clone());
            let serialized_diff =
                borsh::to_vec(&cumulative_state_diff).expect("Diff serialization cannot fail");
            let compressed_diff =
                compress_blob(&serialized_diff).expect("Diff compression cannot fail");

            // check state diff threshold
            if compressed_diff.len() > MAX_TXBODY_SIZE {
                cumulative_state_diff = commitment_state_diff;
                state.add_partition(i - 1, PartitionReason::StateDiff)?;
                continue;
            }
        }

        // Add all remaining commitments as last partition
        state.add_partition(commitments.len() - 1, PartitionReason::Finish)?;

        Ok(state.into_inner())
    }

    fn create_circuit_input(
        &self,
        partition: &Partition<'_>,
    ) -> anyhow::Result<BatchProofCircuitInputV3> {
        let initial_state_root = self
            .ledger_db
            .get_l2_state_root(partition.start_height - 1)
            .context("Failed to get initial state root")?
            .expect("Start l2 height must have state root");
        let final_state_root = self
            .ledger_db
            .get_l2_state_root(partition.end_height)
            .context("Failed to get final state root")?
            .expect("End l2 height must have state root");

        // TODO: REPLACE THIS
        let (
            short_header_proofs,
            state_transition_witnesses,
            cache_prune_l2_heights,
            l2_blocks,
            last_l1_hash_witness,
        ) = get_batch_proof_circuit_input_from_commitments::<Da, _>(
            partition.start_height,
            partition.commitments,
            &self.ledger_db,
            &self.storage_manager,
            &self.sequencer_pub_key,
        )
        .context("Failed to get circuit input from commitments")?;

        let first_commitment = &partition.commitments[0];
        let previous_sequencer_commitment = (first_commitment.index != 1).then(|| {
            self.ledger_db
                .get_commitment_by_index(first_commitment.index - 1)
                .expect("Should get commitment")
                .expect("Commitment should exist")
        });

        Ok(BatchProofCircuitInputV3 {
            initial_state_root,
            final_state_root,
            l2_blocks,
            state_transition_witnesses,
            short_header_proofs,
            sequencer_commitments: partition.commitments.to_vec(),
            cache_prune_l2_heights,
            last_l1_hash_witness,
            previous_sequencer_commitment,
        })
    }

    async fn start_proving(
        &self,
        input: BatchProofCircuitInputV3,
    ) -> anyhow::Result<(Uuid, oneshot::Receiver<Proof>)> {
        let end_l2_height = input
            .sequencer_commitments
            .last()
            .expect("Must have 1")
            .l2_end_block_number;
        let current_spec = fork_from_block_number(end_l2_height).spec_id;

        let elf = self
            .elfs_by_spec
            .get(&current_spec)
            .expect("Every fork should have an elf attached")
            .clone();

        tracing::info!("Starting proving with ELF of spec: {:?}", current_spec);

        let input = borsh::to_vec(&input.into_v3_parts()).expect("Input serialization cannot fail");

        let proof_data = ProofData {
            input,
            assumptions: vec![],
            elf,
        };
        self.prover_service
            .start_proving(proof_data, ReceiptType::Groth16)
            .await
    }

    fn watch_proving_jobs(&self, proving_jobs: Vec<(Uuid, oneshot::Receiver<Proof>)>) {
        assert!(!proving_jobs.is_empty(), "received empty jobs list");

        let ledger_db = self.ledger_db.clone();
        let prover_service = self.prover_service.clone();
        let code_commitments_by_spec = self.code_commitments_by_spec.clone();

        let mut proving_jobs = proving_jobs
            .into_iter()
            .map(|(job_id, rx)| async move {
                let proof = rx.await.expect("Proof channel should never close");
                (job_id, proof)
            })
            .collect::<FuturesUnordered<_>>();

        tokio::spawn(async move {
            while let Some((job_id, proof)) = proving_jobs.next().await {
                info!("Proving job finished {}", job_id);

                let output = extract_proof_output::<Vm>(&proof, &code_commitments_by_spec);

                // stores proof and marks job as waiting for da
                ledger_db
                    .put_proof_by_job_id(job_id, proof.clone(), output.into())
                    .expect("Should put proof to db");

                let tx_id = prover_service
                    .submit_proof(proof)
                    .await
                    .expect("Failed to submit proof");

                info!("Job {} proof sent to DA", job_id);

                // stores tx id and removes job from pending da submission
                ledger_db
                    .finalize_proving_job(job_id, tx_id.into())
                    .expect("Should update proving job tx id");
            }
        });
    }

    #[instrument(name = "recovery", skip_all)]
    async fn recover_proving_sessions(&self) {
        // recover proving sessions
        let proving_jobs = self
            .prover_service
            .start_session_recovery()
            .expect("Failed to start proving session recovery");
        let mut proving_jobs = proving_jobs
            .into_iter()
            .map(|rx| async move { rx.await.expect("Proof recovery channel closed abruptly") })
            .collect::<FuturesUnordered<_>>();

        info!("Recovering {} proving sessions", proving_jobs.len());

        let mut proofs = HashMap::with_capacity(proving_jobs.len());
        while let Some(ProofWithJob { job_id, proof }) = proving_jobs.next().await {
            info!("Proving job finished {}", job_id);

            let output = extract_proof_output::<Vm>(&proof, &self.code_commitments_by_spec);

            // stores proof and marks job as waiting for da
            self.ledger_db
                .put_proof_by_job_id(job_id, proof.clone(), output.into())
                .expect("Should put proof to db");

            info!("Completed proving job {}", job_id);

            proofs.insert(job_id, proof);

            // TODO: there is a quite small chance that proving has started, but job commitment indices
            // pending commitments haven't been updated in db, maybe we should also try to recover that?
        }

        // merge proofs of da submission pending jobs
        let job_ids = self
            .ledger_db
            .get_pending_l1_submission_jobs()
            .expect("Should get pending l1 jobs");
        for job_id in job_ids {
            if let hash_map::Entry::Vacant(entry) = proofs.entry(job_id) {
                let stored_proof = self
                    .ledger_db
                    .get_proof_by_job_id(job_id)
                    .expect("Should get proof by job id")
                    .expect("Proof of job must exist");
                assert_eq!(
                    stored_proof.l1_tx_id, None,
                    "Got pending l1 submission job which contains l1 tx id"
                );
                entry.insert(stored_proof.proof);
            }
        }

        // submit all proofs to da
        for (job_id, proof) in proofs {
            let tx_id = self
                .prover_service
                .submit_proof(proof)
                .await
                .expect("Failed to submit transaction");
            info!("Job {} proof sent to DA", job_id);

            // stores tx id and removes job from pending da submission
            self.ledger_db
                .finalize_proving_job(job_id, tx_id.into())
                .expect("Should update proving job tx id");
        }
    }

    fn get_state_diff(&self, start_height: u64, end_height: u64) -> anyhow::Result<StateDiff> {
        let mut commitment_state_diff = StateDiff::new();
        for l2_height in start_height..=end_height {
            let state_diff = self
                .ledger_db
                .get_l2_state_diff(L2BlockNumber(l2_height))?
                .expect("L2 state diff must exist");
            commitment_state_diff = merge_state_diffs(commitment_state_diff, state_diff);
        }

        Ok(commitment_state_diff)
    }

    fn should_prove(&self) -> bool {
        match self.prover_config.proving_mode {
            // Unconditionally call prove
            ProverGuestRunConfig::ProveWithFakeProofs => true,
            // Call prove with a probability
            _ => {
                self.prover_config.proof_sampling_number == 0
                    || rand::thread_rng().gen_range(0..self.prover_config.proof_sampling_number)
                        == 0
            }
        }
    }
}

const MAX_CUMULATIVE_CACHE_SIZE: usize = 128 * 1024 * 1024;

type CommitmentStateTransitionData = (
    VecDeque<Vec<u8>>,
    VecDeque<Vec<(Witness, Witness)>>,
    Vec<u64>,
    VecDeque<Vec<L2Block>>,
    Witness,
);

pub(crate) fn get_batch_proof_circuit_input_from_commitments<
    Da: DaService,
    DB: BatchProverLedgerOps,
>(
    first_l2_height_of_commitments: u64,
    sequencer_commitments: &[SequencerCommitment],
    ledger_db: &DB,
    storage_manager: &ProverStorageManager,
    sequencer_pub_key: &K256PublicKey,
) -> Result<CommitmentStateTransitionData, anyhow::Error> {
    let mut committed_l2_blocks = VecDeque::with_capacity(sequencer_commitments.len());

    for (idx, sequencer_commitment) in sequencer_commitments.iter().enumerate() {
        // get the l2 height ranges of each seq_commitments

        let start_l2 = if idx == 0 {
            first_l2_height_of_commitments
        } else {
            sequencer_commitments[idx - 1].l2_end_block_number + 1
        };
        let end_l2 = sequencer_commitment.l2_end_block_number;

        let l2_blocks_in_commitment = ledger_db
            .get_l2_block_range(&(L2BlockNumber(start_l2)..=L2BlockNumber(end_l2)))
            .context("Failed to get l2 blocks")?;
        assert_eq!(
            l2_blocks_in_commitment
                .last()
                .expect("at least one must exist")
                .height,
            end_l2,
            "Should not try to create circuit input without ensuring the prover is synced"
        );

        let merkle_root = MerkleTree::<Sha256>::from_leaves(
            l2_blocks_in_commitment
                .iter()
                .map(|block| block.hash)
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .root()
        .expect("Must have at least one l2 block");
        assert_eq!(
            merkle_root, sequencer_commitment.merkle_root,
            "Commitment merkle root mismatch"
        );

        let mut l2_blocks = Vec::with_capacity(l2_blocks_in_commitment.len());

        for l2_block in l2_blocks_in_commitment {
            let l2_block: L2Block = l2_block
                .try_into()
                .context("Failed to parse transactions")?;

            l2_blocks.push(l2_block);
        }
        committed_l2_blocks.push_back(l2_blocks);
    }

    // Replay transactions in the commitment blocks and collect cumulative witnesses
    let (
        state_transition_witnesses,
        cache_prune_l2_heights,
        short_header_proofs,
        last_l1_hash_witness,
    ) = generate_cumulative_witness::<Da, _>(
        &committed_l2_blocks,
        ledger_db,
        storage_manager,
        sequencer_pub_key,
    )?;

    Ok((
        short_header_proofs,
        state_transition_witnesses,
        cache_prune_l2_heights,
        committed_l2_blocks,
        last_l1_hash_witness,
    ))
}

#[allow(clippy::type_complexity)]
fn generate_cumulative_witness<Da: DaService, DB: BatchProverLedgerOps>(
    committed_l2_blocks: &VecDeque<Vec<L2Block>>,
    ledger_db: &DB,
    storage_manager: &ProverStorageManager,
    sequencer_pub_key: &K256PublicKey,
) -> anyhow::Result<(
    VecDeque<Vec<(Witness, Witness)>>,
    Vec<u64>,
    VecDeque<Vec<u8>>,
    Witness, // last hash witness
)> {
    let mut short_header_proofs: VecDeque<Vec<u8>> = VecDeque::new();

    let mut state_transition_witnesses = VecDeque::with_capacity(committed_l2_blocks.len());

    let mut init_state_root = ledger_db
        .get_l2_state_root(committed_l2_blocks[0][0].height() - 1)?
        .expect("L2 state root must exist");

    let mut cumulative_state_log = None;
    let mut cumulative_offchain_log = None;
    let mut cache_prune_l2_heights = vec![];

    let mut stf =
        StfBlueprint::<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>::new();

    let last_l2_height = committed_l2_blocks
        .back()
        .expect("must have at least one commitment")
        .last()
        .expect("must have at least one l2 block")
        .height();

    for l2_blocks_in_commitment in committed_l2_blocks {
        let mut witnesses = Vec::with_capacity(l2_blocks_in_commitment.len());

        SHORT_HEADER_PROOF_PROVIDER
            .get()
            .unwrap()
            .clear_queried_hashes();

        for l2_block in l2_blocks_in_commitment {
            let l2_height = l2_block.height();

            let pre_state = storage_manager.create_storage_for_l2_height(l2_height);
            let current_spec = fork_from_block_number(l2_height).spec_id;

            let silent_subscriber = tracing_subscriber::registry().with(LevelFilter::OFF);
            let l2_block_result = tracing::subscriber::with_default(silent_subscriber, || {
                stf.apply_l2_block(
                    current_spec,
                    sequencer_pub_key,
                    &init_state_root,
                    pre_state,
                    cumulative_state_log.take(),
                    cumulative_offchain_log.take(),
                    Default::default(),
                    Default::default(),
                    l2_block,
                )
            })?;

            assert_eq!(
                l2_block.state_root(),
                l2_block_result.state_root_transition.final_root,
                "State root mismatch when regenerating witnesses"
            );

            init_state_root = l2_block_result.state_root_transition.final_root;

            let mut state_log = l2_block_result.state_log;
            let mut offchain_log = l2_block_result.offchain_log;

            // If cache grew too large, zkvm will error with OOM, hence, we pass
            // when to prune as hint
            if state_log.estimated_cache_size() + offchain_log.estimated_cache_size()
                > MAX_CUMULATIVE_CACHE_SIZE
            {
                state_log.prune_half();
                offchain_log.prune_half();
                cache_prune_l2_heights.push(l2_height);
            }

            cumulative_state_log = Some(state_log);
            cumulative_offchain_log = Some(offchain_log);

            witnesses.push((l2_block_result.witness, l2_block_result.offchain_witness));
        }

        let new_hashes = SHORT_HEADER_PROOF_PROVIDER
            .get()
            .unwrap()
            .take_queried_hashes(
                l2_blocks_in_commitment[0].height()
                    ..=l2_blocks_in_commitment
                        .last()
                        .expect("must have at least one")
                        .height(),
            );

        for hash in new_hashes {
            let serialized_shp = ledger_db
                .get_short_header_proof_by_l1_hash(&hash)?
                .expect("Should exist");

            short_header_proofs.push_back(serialized_shp);
        }

        state_transition_witnesses.push_back(witnesses);
    }

    let mut last_l1_hash_witness = Witness::default();
    // if post tangerine we always need to read the last L1 hash on Bitcoin Light Client contract
    // if the provider have some hashes, circuit will use that.
    if short_header_proofs.is_empty() {
        let cumulative_state_log = cumulative_state_log.unwrap();
        let prover_storage = storage_manager.create_storage_for_l2_height(last_l2_height + 1);

        // we don't care about the return here
        // we only care about the last hash witness getting filled (or not)
        let _ = citrea_stf::verifier::get_last_l1_hash_on_contract::<DefaultContext>(
            cumulative_state_log,
            prover_storage,
            &mut last_l1_hash_witness,
            [0u8; 32], // final state root is only needed for JMT proof verification
        );
    }

    Ok((
        state_transition_witnesses,
        cache_prune_l2_heights,
        short_header_proofs,
        last_l1_hash_witness,
    ))
}

fn extract_proof_output<Vm: ZkvmHost>(
    proof: &Proof,
    code_commitments_by_spec: &HashMap<SpecId, Vm::CodeCommitment>,
) -> BatchProofCircuitOutput {
    let output = Vm::extract_output::<BatchProofCircuitOutput>(proof)
        .expect("Failed to extract batch proof output");

    let last_l2_height = match &output {
        BatchProofCircuitOutput::V3(v3) => v3.last_l2_height,
    };
    let spec = fork_from_block_number(last_l2_height).spec_id;

    let code_commitment = code_commitments_by_spec
        .get(&spec)
        .expect("Proof public input must contain valid spec id");

    info!("Verifying proof with image ID: {:?}", code_commitment);

    Vm::verify(proof.as_slice(), code_commitment).expect("Failed to verify proof");

    debug!("circuit output: {:?}", output);
    output
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use citrea_common::BatchProverConfig;
    use citrea_primitives::forks::FORKS;
    use citrea_primitives::MAX_TXBODY_SIZE;
    use prover_services::{ParallelProverService, ProofGenMode};
    use sov_db::ledger_db::{BatchProverLedgerOps, LedgerDB, SharedLedgerOps};
    use sov_db::rocks_db_config::RocksdbConfig;
    use sov_db::schema::tables::BATCH_PROVER_LEDGER_TABLES;
    use sov_db::schema::types::L2BlockNumber;
    use sov_mock_da::{MockAddress, MockDaService};
    use sov_mock_zkvm::MockZkvm;
    use sov_modules_api::fork::Fork;
    use sov_modules_api::{L2Block, SpecId};
    use sov_prover_storage_manager::ProverStorageManager;
    use sov_rollup_interface::block::{L2Header, SignedL2Header};
    use sov_rollup_interface::da::SequencerCommitment;
    use tempfile::TempDir;
    use tokio::sync::{broadcast, mpsc};

    use super::{Prover, ProverRequest};
    use crate::PartitionMode;

    // This might be a bit problematic if another unit test in this crate wants
    // to use different set of forks for any reason.
    const TEST_FORKS: &[Fork] = &[
        Fork::new(SpecId::Tangerine, 0),
        Fork::new(SpecId::Fork3, 10),
    ];

    struct MockProverData {
        prover: Prover<MockDaService, LedgerDB, MockZkvm>,
        _l1_signal_tx: mpsc::Sender<()>,
        _l2_block_tx: broadcast::Sender<u64>,
        _request_tx: mpsc::Sender<ProverRequest>,
    }

    fn create_mock_prover() -> MockProverData {
        let _ = FORKS.set(TEST_FORKS);

        let tmpdir = TempDir::new().unwrap();
        let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(
            tmpdir.path(),
            None,
            Some(
                BATCH_PROVER_LEDGER_TABLES
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            ),
        ))
        .unwrap();
        let storage_manager = ProverStorageManager::new(sov_state::Config {
            path: tmpdir.path().to_path_buf(),
            db_max_open_files: None,
        })
        .unwrap();
        let da_service = Arc::new(MockDaService::new(
            MockAddress::from([2; 32]),
            tmpdir.path(),
        ));
        let vm = MockZkvm::new();
        let prover_service =
            Arc::new(ParallelProverService::new(da_service, vm, ProofGenMode::Execute, 1).unwrap());

        let (l1_signal_tx, l1_signal_rx) = mpsc::channel(1);
        let (l2_block_tx, l2_block_rx) = broadcast::channel(4);
        let (request_tx, request_rx) = mpsc::channel(4);

        let prover = Prover::new(
            BatchProverConfig::default(),
            ledger_db,
            storage_manager,
            prover_service,
            vec![2; 33],
            Default::default(),
            Default::default(),
            l1_signal_rx,
            l2_block_rx,
            request_rx,
        );

        MockProverData {
            prover,
            _l1_signal_tx: l1_signal_tx,
            _l2_block_tx: l2_block_tx,
            _request_tx: request_tx,
        }
    }

    fn put_l2_blocks(ledger_db: &LedgerDB, l2_block_data: Vec<(u64, usize)>) {
        for (l2_height, diff_size) in l2_block_data {
            let l2_block = L2Block::new(
                SignedL2Header::new(
                    L2Header::new(l2_height, [0; 32], [0; 32], 0, [0; 32], 0),
                    [0; 32],
                    vec![],
                ),
                vec![],
            );
            ledger_db.commit_l2_block(l2_block, vec![], None).unwrap();
            // random key to ensures that with each block state size grows consistently
            let state_key = Arc::from(rand::random::<u64>().to_le_bytes());
            // random value ensures that the borsh can not compress properly
            let state_value = Some(Arc::from_iter(
                vec![0; diff_size].into_iter().map(|_| rand::random::<u8>()),
            ));
            let state_diff = vec![(state_key, state_value)];
            ledger_db
                .set_l2_state_diff(L2BlockNumber(l2_height), state_diff)
                .unwrap();
        }
    }

    fn put_commitments(ledger_db: &LedgerDB, commitments: &[SequencerCommitment]) {
        for commitment in commitments {
            ledger_db.put_commitment_by_index(commitment).unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn simple_commitment_partition() {
        let MockProverData { mut prover, .. } = create_mock_prover();
        // put 3 l2 blocks with 0 diff size
        put_l2_blocks(&prover.ledger_db, vec![(1, 0), (2, 0), (3, 0)]);

        // 1 small commitment should produce 1 partition
        {
            let mut commitments = vec![SequencerCommitment {
                merkle_root: [0; 32],
                index: 1,
                l2_end_block_number: 3,
            }];
            put_commitments(&prover.ledger_db, &commitments);

            let partitions = prover
                .create_partitions(&mut commitments, PartitionMode::Normal)
                .unwrap();
            assert_eq!(partitions.len(), 1);
            let partition = &partitions[0];
            assert_eq!(partition.start_height, 1);
            assert_eq!(partition.end_height, 3);
            assert_eq!(partition.commitments.len(), 1);
        }

        // override previous commitment index 1 here as well
        let mut commitments = vec![
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 1,
                l2_end_block_number: 2,
            },
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 2,
                l2_end_block_number: 3,
            },
        ];
        put_commitments(&prover.ledger_db, &commitments);

        // 2 consecutive small commitments should produce 1 partition
        {
            let partitions = prover
                .create_partitions(&mut commitments, PartitionMode::Normal)
                .unwrap();
            assert_eq!(partitions.len(), 1);
            let partition = &partitions[0];
            assert_eq!(partition.start_height, 1);
            assert_eq!(partition.end_height, 3);
            assert_eq!(partition.commitments.len(), 2);
        }

        // test OneByOne partition mode
        {
            let partitions = prover
                .create_partitions(&mut commitments, PartitionMode::OneByOne)
                .unwrap();
            assert_eq!(partitions.len(), 2);

            let partition_1 = &partitions[0];
            assert_eq!(partition_1.start_height, 1);
            assert_eq!(partition_1.end_height, 2);
            assert_eq!(partition_1.commitments.len(), 1);

            let partition_2 = &partitions[1];
            assert_eq!(partition_2.start_height, 3);
            assert_eq!(partition_2.end_height, 3);
            assert_eq!(partition_2.commitments.len(), 1);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn commitment_partition_with_index_gap() {
        let MockProverData { mut prover, .. } = create_mock_prover();
        // put 4 l2 blocks
        put_l2_blocks(&prover.ledger_db, vec![(1, 0), (2, 0), (3, 0), (4, 0)]);

        // commitments with index gap should create 2 partitions
        let mut commitments = vec![
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 1,
                l2_end_block_number: 1,
            },
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 3,
                l2_end_block_number: 3,
            },
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 4,
                l2_end_block_number: 4,
            },
        ];
        put_commitments(&prover.ledger_db, &commitments);

        let partitions = prover
            .create_partitions(&mut commitments, PartitionMode::Normal)
            .unwrap();
        assert_eq!(partitions.len(), 2);
        let partition_1 = &partitions[0];
        assert_eq!(partition_1.start_height, 1);
        assert_eq!(partition_1.end_height, 1);
        assert_eq!(partition_1.commitments.len(), 1);
        // index 3 should be filtered due to prev missing, and index 4 should be the 2nd partition
        let partition_2 = &partitions[1];
        assert_eq!(partition_2.start_height, 4);
        assert_eq!(partition_2.end_height, 4);
        assert_eq!(partition_2.commitments.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn commitment_partition_with_state_diff() {
        let MockProverData { mut prover, .. } = create_mock_prover();
        // put 3 l2 blocks with total state diff of 1.33 * maxsize
        put_l2_blocks(
            &prover.ledger_db,
            vec![
                (1, 0),
                (2, MAX_TXBODY_SIZE * 2 / 3),
                (3, MAX_TXBODY_SIZE * 2 / 3),
            ],
        );

        // commitments with big state diff will create partitions (block 2 and 3)
        let mut commitments = vec![
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 1,
                l2_end_block_number: 1,
            },
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 2,
                l2_end_block_number: 2,
            },
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 3,
                l2_end_block_number: 3,
            },
        ];
        put_commitments(&prover.ledger_db, &commitments);

        let partitions = prover
            .create_partitions(&mut commitments, PartitionMode::Normal)
            .unwrap();
        assert_eq!(partitions.len(), 2);
        let partition_1 = &partitions[0];
        assert_eq!(partition_1.start_height, 1);
        assert_eq!(partition_1.end_height, 2);
        assert_eq!(partition_1.commitments.len(), 2);

        let partition_2 = &partitions[1];
        assert_eq!(partition_2.start_height, 3);
        assert_eq!(partition_2.end_height, 3);
        assert_eq!(partition_2.commitments.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn commitment_partition_with_spec_change() {
        let MockProverData { mut prover, .. } = create_mock_prover();
        // put 4 l2 blocks where l2 blocks are switching to a new fork
        put_l2_blocks(&prover.ledger_db, vec![(8, 0), (9, 0), (10, 0), (11, 0)]);

        let mut commitments = vec![
            // index 2 is going to be filtered because index 1 is unknown
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 2,
                l2_end_block_number: 7,
            },
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 3,
                l2_end_block_number: 8,
            },
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 4,
                l2_end_block_number: 10,
            },
            SequencerCommitment {
                merkle_root: [0; 32],
                index: 5,
                l2_end_block_number: 11,
            },
        ];
        put_commitments(&prover.ledger_db, &commitments);

        let partitions = prover
            .create_partitions(&mut commitments, PartitionMode::Normal)
            .unwrap();
        assert_eq!(partitions.len(), 2);
        // first partition is commitment index 3
        let partition_1 = &partitions[0];
        assert_eq!(partition_1.start_height, 8);
        assert_eq!(partition_1.end_height, 8);
        assert_eq!(partition_1.commitments.len(), 1);

        // second partitions is commitment indices 4 and 5
        let partition_2 = &partitions[1];
        assert_eq!(partition_2.start_height, 9);
        assert_eq!(partition_2.end_height, 11);
        assert_eq!(partition_2.commitments.len(), 2);
    }
}
