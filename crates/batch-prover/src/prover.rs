use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use citrea_common::utils::merge_state_diffs;
use citrea_common::{BatchProverConfig, ProverGuestRunConfig};
use citrea_primitives::compression::compress_blob;
use citrea_primitives::forks::fork_from_block_number;
use citrea_primitives::MAX_TXBODY_SIZE;
use prover_services::{ParallelProverService, ProofData};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::L2BlockNumber;
use sov_keys::default_signature::K256PublicKey;
use sov_modules_api::{SpecId, StateDiff, Zkvm};
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::batch_proof::input::v3::BatchProofCircuitInputV3;
use sov_rollup_interface::zk::{Proof, ReceiptType, ZkvmHost};
use tokio::select;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::proving::get_batch_proof_circuit_input_from_commitments;

pub struct Prover<Da, DB, Vm>
where
    Da: DaService,
    DB: BatchProverLedgerOps,
    Vm: ZkvmHost + Zkvm + 'static,
{
    prover_config: BatchProverConfig,
    ledger_db: DB,
    storage_manager: ProverStorageManager,
    prover_service: Arc<ParallelProverService<Da, Vm>>,
    sequencer_pub_key: K256PublicKey,
    elfs_by_spec: HashMap<SpecId, Vec<u8>>,
    l1_signal_rx: mpsc::Receiver<()>,
    l2_block_rx: broadcast::Receiver<u64>,
    sync_target_l2_height: Option<u64>,
}

impl<Da, DB, Vm> Prover<Da, DB, Vm>
where
    Da: DaService,
    DB: BatchProverLedgerOps,
    Vm: ZkvmHost + Zkvm,
{
    pub fn new(
        prover_config: BatchProverConfig,
        ledger_db: DB,
        storage_manager: ProverStorageManager,
        prover_service: Arc<ParallelProverService<Da, Vm>>,
        sequencer_pub_key: Vec<u8>,
        elfs_by_spec: HashMap<SpecId, Vec<u8>>,
        l1_signal_rx: mpsc::Receiver<()>,
        l2_block_rx: broadcast::Receiver<u64>,
    ) -> Self {
        Self {
            prover_config,
            ledger_db,
            storage_manager,
            prover_service,
            sequencer_pub_key: K256PublicKey::try_from(sequencer_pub_key.as_slice())
                .expect("Invalid sequencer public key"),
            elfs_by_spec,
            l1_signal_rx,
            l2_block_rx,
            sync_target_l2_height: None,
        }
    }

    pub async fn run(mut self, cancellation_token: CancellationToken) {
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                }
                l1_signal = self.l1_signal_rx.recv() => {
                    l1_signal.expect("L1 signal sender channel closed abruptly");

                    if let Err(e) = self.try_proving().await {
                        error!("Failed to start proving: {:?}", e);
                    }
                },
                l2_signal = self.l2_block_rx.recv() => {
                    let l2_height = l2_signal.expect("L2 signal sender channel closed abruptly");
                    let Some(sync_target_l2_height) = self.sync_target_l2_height else {
                        // we are already fully synced or no commitments are waiting for l2 blocks, ignore
                        continue;
                    };

                    if l2_height < sync_target_l2_height {
                        // new l2 height has not yet reached the next sync target, ignore
                        continue;
                    }
                }
            }
        }
    }

    async fn try_proving(&mut self) -> anyhow::Result<()> {
        if !self.should_prove() {
            info!("Skipping proving due to sampling");
            return Ok(());
        }

        let commitments = self.get_pending_commitments()?;
        if commitments.is_empty() {
            info!("No pending commitments found");
            return Ok(());
        }
        info!("Have {} pending commitment(s)", commitments.len());

        let commitments = self.filter_unsynced_commitments(commitments)?;
        if commitments.is_empty() {
            return Ok(());
        }
        info!("Processing {} commitment(s)", commitments.len());

        let partitions = self.partition_commitments(&commitments, PartitionMode::Normal)?;
        info!("Partitioned commitments into {} parts", partitions.len());

        let mut proof_rxs = Vec::with_capacity(partitions.len());
        for partition in partitions {
            let input = self
                .create_circuit_input(&partition)
                .await
                .context("Failed to create circuit input")?;

            let rx = self.start_proving(input).await;
            proof_rxs.push(rx);

            for commitment in partition.commitments {
                self.ledger_db
                    .delete_pending_commitment(commitment.index)
                    .context("Failed to set commitment status to running")?;
            }
        }

        // TODO: spawn a task that waits for proof tasks and delete their status, and update l2 block status to proven
        // TODO: think about how to handle insert_batch_proof_data_by_l1_height

        Ok(())
    }

    fn get_pending_commitments(&self) -> anyhow::Result<Vec<SequencerCommitment>> {
        let pending_commitment_indices = self.ledger_db.get_pending_commitments()?;

        let mut commitments = Vec::with_capacity(pending_commitment_indices.len());
        for index in pending_commitment_indices {
            let commitment = self
                .ledger_db
                .get_commitment_by_index(index)?
                .expect("Unproven commitment must exist by index");
            commitments.push(commitment);
        }

        commitments.sort();

        Ok(commitments)
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

    /// Partition the commitments into provable chunks. Here are the rules when partitioning in Normal mode:
    /// 1. If there is an index gap in between commitments, partition is formed
    /// 2. If ƒork has changed, partition is formed
    /// 3. If max state diff limit is surpassed, partition is formed
    fn partition_commitments<'a>(
        &self,
        commitments: &'a [SequencerCommitment],
        mode: PartitionMode,
    ) -> anyhow::Result<Vec<Partition<'a>>> {
        let start_l2_height = if commitments[0].index == 0 {
            // If this is the first commitment ever, start from 1
            1
        } else {
            let previous_commitment_index = commitments[0].index - 1;
            // If this is not the first commitment, start l2 height will be end block number + 1 of the previous commitment
            self.ledger_db
                .get_commitment_by_index(previous_commitment_index)?
                .expect("Previous commitment must exist")
                .l2_end_block_number
                + 1
        };

        let mut state = PartitionState::new(commitments, start_l2_height);

        if mode == PartitionMode::OneByOne {
            let mut commitment_start_height = start_l2_height;
            for (i, commitment) in commitments.iter().enumerate() {
                let commitment_end_height = commitment.l2_end_block_number;

                let commitment_state_diff =
                    self.get_state_diff(commitment_start_height, commitment_end_height)?;
                assert_state_diff_threshold(&commitment_state_diff);

                commitment_start_height = commitment_end_height + 1;

                state.add_partition(i, "onebyone");
            }
            return Ok(state.into_inner());
        }

        // Normal partition mode

        let mut cumulative_state_diff = StateDiff::new();
        let mut commitment_start_height = start_l2_height;

        for (i, commitment) in commitments.iter().enumerate() {
            let commitment_end_height = commitment.l2_end_block_number;

            let commitment_state_diff =
                self.get_state_diff(commitment_start_height, commitment_end_height)?;

            commitment_start_height = commitment_end_height + 1;

            // check index gap
            if i != 0 && commitment.index != commitments[i - 1].index + 1 {
                assert_state_diff_threshold(&commitment_state_diff);
                cumulative_state_diff = commitment_state_diff;
                state.add_partition(i - 1, "indexgap"); // i - 1 because inclusive
                continue;
            }

            // check spec change
            let current_spec = fork_from_block_number(commitment_end_height);
            if i != 0
                && current_spec != fork_from_block_number(commitments[i - 1].l2_end_block_number)
            {
                assert_state_diff_threshold(&commitment_state_diff);
                cumulative_state_diff = commitment_state_diff;
                state.add_partition(i - 1, "specchange"); // i - 1 because inclusive
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
                assert_state_diff_threshold(&commitment_state_diff);
                cumulative_state_diff = commitment_state_diff;
                state.add_partition(i - 1, "statediff"); // i - 1 because inclusive
                continue;
            }
        }

        // Add all remaining commitments as last partition
        state.add_partition(commitments.len() - 1, "finish");

        Ok(state.into_inner())
    }

    async fn create_circuit_input(
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
        .await
        .context("Failed to get circuit input from commitments")?;

        let previous_sequencer_commitment = partition
            .commitments
            .first()
            .expect("Must have 1")
            .index
            .checked_sub(1)
            .map(|index| {
                self.ledger_db
                    .get_commitment_by_index(index)
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

    async fn start_proving(&self, input: BatchProofCircuitInputV3) -> oneshot::Receiver<Proof> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Enum to determine how to group commitments
pub enum PartitionMode {
    /// Groups commitments the normal way
    /// Generates proof(s) given l1 height using the same strategy of batch prover
    Normal,
    /// Every commitment is a group on their own
    /// Generates a proof for every commitment
    OneByOne,
}

struct PartitionState<'a> {
    commitments: &'a [SequencerCommitment],
    partitions: Vec<Partition<'a>>,
    partition_start_height: u64,
    partition_start_idx: usize,
}

impl<'a> PartitionState<'a> {
    fn new(commitments: &'a [SequencerCommitment], start_l2_height: u64) -> Self {
        Self {
            commitments,
            partitions: vec![],
            partition_start_height: start_l2_height,
            partition_start_idx: 0,
        }
    }

    /// Adds a new partition. end_idx is the index to the commitments array, and it is inclusive.
    fn add_partition(&mut self, end_idx: usize, reason: &str) {
        assert!(
            end_idx >= self.partition_start_idx,
            "incorrectly ordered end partition index"
        );
        assert!(
            end_idx < self.commitments.len(),
            "end index higher than commitment count"
        );

        let first_commitment = &self.commitments[self.partition_start_idx];
        let last_commitment = &self.commitments[end_idx];

        info!(
            "Adding commitment partition: indices=[{},{}] blocks=[{},{}] reason={}",
            first_commitment.index,
            last_commitment.index,
            self.partition_start_height,
            last_commitment.l2_end_block_number,
            reason
        );

        let commitments = &self.commitments[self.partition_start_idx..=end_idx];
        self.partitions.push(Partition {
            commitments,
            start_height: self.partition_start_height,
            end_height: last_commitment.l2_end_block_number,
        });

        self.partition_start_idx = end_idx + 1;
        self.partition_start_height = last_commitment.l2_end_block_number + 1;
    }

    fn into_inner(self) -> Vec<Partition<'a>> {
        assert_eq!(
            self.partition_start_idx,
            self.commitments.len(),
            "trying to finalize partition without adding all commitments"
        );
        self.partitions
    }
}

/// Helper wrapper struct to hold start and end heights with the commitment partition
struct Partition<'a> {
    commitments: &'a [SequencerCommitment],
    start_height: u64,
    end_height: u64,
}

#[inline(always)]
fn assert_state_diff_threshold(state_diff: &StateDiff) {
    let serialized_diff = borsh::to_vec(state_diff).expect("Diff serialization cannot fail");
    let compressed_diff = compress_blob(&serialized_diff).expect("Diff compression cannot fail");
    assert!(
        compressed_diff.len() > MAX_TXBODY_SIZE,
        "Got single commitment bigger than txbody limit"
    );
}
