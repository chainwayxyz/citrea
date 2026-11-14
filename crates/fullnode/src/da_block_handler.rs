//! Data Availability (DA) block handling for the fullnode
//!
//! This module is responsible for processing L1 blocks, extracting and verifying
//! sequencer commitments and ZK proofs, and tracking L2 finality.

use core::panic;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::{extract_zk_proofs_and_sequencer_commitments, sync_l1, ProofOrCommitment};
use citrea_common::utils::{
    exceeded_stop_height, get_tangerine_activation_height_non_zero, shutdown_requested,
};
use citrea_common::StartVariant;
use citrea_primitives::forks::proof_guest_spec_id;
use citrea_primitives::network_to_dev_mode;
use citrea_primitives::risc0_cutoff::risc0_cutoff;
use reth_tasks::shutdown::GracefulShutdown;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::NodeLedgerOps;
use sov_db::schema::types::l2_block::StoredL2Block;
use sov_db::schema::types::{L2BlockNumber, L2HeightAndIndex, L2HeightStatus, SlotNumber};
use sov_modules_api::{DaSpec, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use sov_rollup_interface::Network;
use tokio::select;
use tokio::sync::{Mutex, Notify};
use tracing::{debug, error, info, instrument, warn};

use crate::error::{CommitmentError, HaltingError, ProcessingError, ProofError, SkippableError};
use crate::metrics::FULLNODE_METRICS as FM;

/// Result of processing a commitment or proof
enum ProcessingResult {
    /// Processing completed successfully
    Success,
    /// Item was discarded due to failure or irrelevance
    Discarded,
    /// Processing deferred, waiting for dependencies
    Pending,
}

/// Origin of a proof currently being processed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofSource {
    /// Proof extracted from DA blobs in the currently scanned L1 block.
    FromL1,
    /// Proof loaded from the pending proofs table for retry.
    FromPendingRetry,
}

/// Handler for processing L1 blocks and their contained proofs and commitments
///
/// This component is responsible for:
/// - Synchronizing L1 blocks
/// - Processing sequencer commitments
/// - Verifying ZK proofs
/// - Maintaining block processing order
/// - Managing the backup state
pub struct L1BlockHandler<Vm, Da, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: NodeLedgerOps,
{
    /// Database for ledger operations
    ledger_db: DB,
    /// Data availability service instance
    da_service: Arc<Da>,
    /// Sequencer's DA public key for verifying commitments
    sequencer_da_pub_key: Vec<u8>,
    /// Prover's DA public key for verifying proofs
    prover_da_pub_key: Vec<u8>,
    /// Map of ZKVM code commitments by spec ID
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    /// Cache for L1 block data
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    /// Queue of L1 blocks waiting to be processed
    queued_l1_blocks: Arc<Mutex<VecDeque<<Da as DaService>::FilteredBlock>>>,
    /// Manager for backup operations
    backup_manager: Arc<BackupManager>,
    /// Citrea network the node is operating on
    network: Network,
    /// Inclusive L1 publication height through which the prover's DA signature is trusted.
    risc0_cutoff_l1_height: Option<u64>,
    /// Optional L1 height at which to stop syncing (debug/testing)
    stop_at_l1_height: Option<u64>,
}

impl<Vm, Da, DB> L1BlockHandler<Vm, Da, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: NodeLedgerOps + Clone,
{
    /// Creates a new L1BlockHandler instance
    ///
    /// # Arguments
    /// * `ledger_db` - Database for ledger operations
    /// * `da_service` - Data availability service
    /// * `sequencer_da_pub_key` - Sequencer's DA public key
    /// * `prover_da_pub_key` - Prover's DA public key
    /// * `code_commitments_by_spec` - Map of ZKVM code commitments
    /// * `l1_block_cache` - Cache for L1 block data
    /// * `backup_manager` - Manager for backup operations
    /// * `stop_at_l1_height` - Optional L1 height at which to stop syncing (debug/testing)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: Network,
        ledger_db: DB,
        da_service: Arc<Da>,
        sequencer_da_pub_key: Vec<u8>,
        prover_da_pub_key: Vec<u8>,
        code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
        l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
        backup_manager: Arc<BackupManager>,
        stop_at_l1_height: Option<u64>,
    ) -> Self {
        Self {
            ledger_db,
            da_service,
            sequencer_da_pub_key,
            prover_da_pub_key,
            code_commitments_by_spec,
            l1_block_cache,
            queued_l1_blocks: Arc::new(Mutex::new(VecDeque::new())),
            backup_manager,
            network,
            risc0_cutoff_l1_height: risc0_cutoff(network).map(|cutoff| cutoff.l1_height()),
            stop_at_l1_height,
        }
    }

    /// Runs the L1BlockHandler service
    ///
    /// This method continuously:
    /// 1. Syncs new L1 blocks from the DA layer
    /// 2. Processes queued blocks to extract commitments and proofs
    /// 3. Verifies and applies the extracted data
    /// 4. Updates the chain state accordingly
    ///
    /// # Arguments
    /// * `l1_start_variant` - Variant indicating where to start syncing L1 blocks from
    /// * `shutdown_signal` - Signal to gracefully shut down
    #[instrument(name = "L1BlockHandler", skip_all)]
    pub async fn run(
        mut self,
        l1_start_variant: StartVariant,
        mut shutdown_signal: GracefulShutdown,
    ) {
        let notifier = Arc::new(Notify::new());
        let start_l1_height = l1_start_variant.start_height();

        let l1_sync_worker = sync_l1(
            start_l1_height,
            self.da_service.clone(),
            self.queued_l1_blocks.clone(),
            self.l1_block_cache.clone(),
            notifier.clone(),
        );
        tokio::pin!(l1_sync_worker);

        tokio::time::sleep(Duration::from_secs(1)).await; // Gives time for queue to fill up on startup
        loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    info!("Shutting down L1BlockHandler");
                    return;
                }
                _ = &mut l1_sync_worker => {},
                _ = notifier.notified() => {
                    if let Err(e) = self.process_queued_l1_blocks(&shutdown_signal).await {
                        error!("{e}");
                        return;
                    }
                },
            }
        }
    }

    /// Processes L1 blocks waiting in the queue
    async fn process_queued_l1_blocks(
        &mut self,
        shutdown_signal: &GracefulShutdown,
    ) -> Result<(), anyhow::Error> {
        loop {
            if shutdown_requested(shutdown_signal) {
                info!("Shutting down L1BlockHandler");
                return Ok(());
            }

            let Some(l1_block) = self.queued_l1_blocks.lock().await.front().cloned() else {
                break;
            };

            if let Some(stop_height) =
                exceeded_stop_height(l1_block.header().height(), self.stop_at_l1_height)
            {
                bail!("Reached target L1 height {stop_height}");
            }

            self.process_l1_block(l1_block).await?;
            self.queued_l1_blocks.lock().await.pop_front();
        }

        Ok(())
    }

    /// Processes a single L1 block
    ///
    /// # Arguments
    /// * `l1_block` - The L1 block to process
    ///
    /// This method:
    /// 1. Saves the block's short header proof
    /// 2. Records block height mapping
    /// 3. Extracts and processes contained ZK proofs and commitments
    async fn process_l1_block(&mut self, l1_block: Da::FilteredBlock) -> anyhow::Result<()> {
        let start_scanning = Instant::now();
        let _l1_lock = self.backup_manager.start_l1_processing().await;

        let short_header_proof: <<Da as DaService>::Spec as DaSpec>::ShortHeaderProof =
            Da::block_to_short_header_proof(l1_block.clone());
        self.ledger_db.put_short_header_proof_by_l1_hash(
            &l1_block.header().hash().into(),
            borsh::to_vec(&short_header_proof).expect("Should serialize short header proof"),
        )?;

        let l1_height = l1_block.header().height();
        info!("Processing L1 block at height: {}", l1_height);

        // Set the l1 height of the l1 hash
        self.ledger_db
            .set_l1_height_of_l1_hash(l1_block.header().hash().into(), l1_height)?;

        let commitments_and_proofs = extract_zk_proofs_and_sequencer_commitments(
            self.da_service.clone(),
            &l1_block,
            &self.prover_da_pub_key,
            &self.sequencer_da_pub_key,
        )
        .await;

        for commitment_or_proof in commitments_and_proofs {
            match commitment_or_proof {
                ProofOrCommitment::Commitment(commitment) => {
                    if commitment.index == 0 {
                        // Skip the commitment if the index is 0 as the first commitment index is 1
                        // and commitment index can never be 0
                        error!(
                            "Detected sequencer commitment with index 0 at L1 height {}, skipping...",
                            &l1_block.header().height()
                        );
                        continue;
                    }
                    let start_commitment_process = std::time::Instant::now();
                    if let Err(e) = self
                        .process_sequencer_commitment(
                            l1_block.header().height(),
                            l1_block.header().height(),
                            &commitment,
                        )
                        .await
                    {
                        match e {
                            ProcessingError::HaltingError(HaltingError::Commitment(e)) => {
                                error!(
                                    "Halting error while processing sequencer commitment: {e:?}"
                                );
                                return Err(HaltingError::Commitment(e).into());
                            }
                            _ => {
                                unreachable!("Failed to process sequencer commitment: {e:?}");
                            }
                        }
                    }
                    FM.sequencer_commitment_processing_time.record(
                        Instant::now()
                            .saturating_duration_since(start_commitment_process)
                            .as_secs_f64(),
                    );
                }
                ProofOrCommitment::Proof(proof) => {
                    let start_proof_process = std::time::Instant::now();
                    if let Err(e) = self
                        .process_zk_proof(
                            l1_block.header().height(),
                            l1_block.header().height(),
                            proof,
                            ProofSource::FromL1,
                        )
                        .await
                    {
                        match e {
                            ProcessingError::HaltingError(HaltingError::Proof(e)) => {
                                unreachable!("Halting error while processing zk proof: {e:?}");
                                // return Err(HaltingError::Proof(e).into());
                            }
                            _ => {
                                warn!("Could not process ZK proofs: {e}... skipping...");
                            }
                        }
                    }
                    FM.batch_proof_processing_time.record(
                        Instant::now()
                            .saturating_duration_since(start_proof_process)
                            .as_secs_f64(),
                    );
                }
            }
        }

        if let Err(e) = self
            .process_pending_commitments(l1_block.header().height())
            .await
        {
            match e {
                ProcessingError::HaltingError(HaltingError::Commitment(e)) => {
                    error!("Halting error while processing pending commitments: {e:?}");
                    return Err(HaltingError::Commitment(e).into());
                }
                _ => {
                    unreachable!("Failed to process pending commitments: {e:?}");
                }
            }
        }

        if let Err(e) = self
            .process_pending_proofs(l1_block.header().height())
            .await
        {
            match e {
                ProcessingError::HaltingError(HaltingError::Proof(e)) => {
                    unreachable!("Halting error while processing pending proofs: {e:?}");
                    // return Err(HaltingError::Proof(e).into());
                }
                _ => {
                    error!("Failed to process pending proofs: {e:?}");
                }
            }
        }

        self.ledger_db
            .set_last_scanned_l1_height(SlotNumber(l1_height))
            .map_err(|e| anyhow!("Could not set last scanned l1 height: {e}"))?;

        FM.current_l1_block.set(l1_height as f64);
        FM.set_scan_l1_block_duration(
            Instant::now()
                .saturating_duration_since(start_scanning)
                .as_secs_f64(),
        );

        Ok(())
    }

    /// Processes a sequencer commitment found in an L1 block
    ///
    /// This method validates and processes sequencer commitments that are posted to L1. Each commitment
    /// represents a batch of L2 blocks and contains a merkle root of their block hashes. The method:
    /// 1. Validates that the commitment advances chain state (increasing height/index)
    /// 2. Verifies the commitment's merkle root matches the actual L2 blocks
    /// 3. Handles dependencies by storing commitments as pending if prerequisites aren't met
    /// 4. Updates the chain's commitment status once validation succeeds
    ///
    /// The method implements strict ordering - commitments must be processed in sequence and each must
    /// build on the previous one. If a commitment's dependencies aren't met (e.g. missing previous
    /// commitment or L2 blocks not synced), it's stored as pending for later processing.
    ///
    /// # Arguments
    /// * `current_l1_block_height` - Current L1 block being processed
    /// * `found_in_l1_block_height` - L1 block where commitment was found
    /// * `sequencer_commitment` - The commitment to process
    ///
    /// # Returns
    /// The processing result indicating:
    /// - Success: Commitment was valid and processed
    /// - Discarded: Commitment was invalid or redundant
    /// - Pending: Commitment needs prerequisites before processing
    async fn process_sequencer_commitment(
        &self,
        current_l1_block_height: u64,
        found_in_l1_block_height: u64,
        sequencer_commitment: &SequencerCommitment,
    ) -> Result<ProcessingResult, ProcessingError> {
        // Skip if this commitment index was already processed
        // This prevents double-processing and handles conflicting commitments
        if let Some(existing_commitment) = self
            .ledger_db
            .get_commitment_by_index(sequencer_commitment.index)?
        {
            // Check if the new commitment has a different merkle root but keep the first processed one as canonical
            if existing_commitment.merkle_root != sequencer_commitment.merkle_root {
                warn!(
                    "Conflicting sequencer commitments with different merkle roots at index: {}.
                    Already processed merkle root: 0x{}, conflicting merkle root: 0x{}",
                    sequencer_commitment.index,
                    hex::encode(existing_commitment.merkle_root),
                    hex::encode(sequencer_commitment.merkle_root)
                );
            } else {
                warn!(
                    "Duplicate sequencer commitments with same merkle root {} at index: {}.",
                    hex::encode(existing_commitment.merkle_root),
                    sequencer_commitment.index,
                );
            }
            return Ok(ProcessingResult::Discarded);
        }

        // Skip if a different commitment is already pending at this index
        // The first commitment seen at an index stays canonical, even while it is still pending
        if let Some((pending_commitment, _)) = self
            .ledger_db
            .get_pending_commitment_by_index(sequencer_commitment.index)?
        {
            if pending_commitment != *sequencer_commitment {
                warn!(
                    "Conflicting sequencer commitment at index {}.\nAlready pending: {:?}\nConflicting: {:?}",
                    sequencer_commitment.index, pending_commitment, sequencer_commitment
                );
                return Ok(ProcessingResult::Discarded);
            }
        }

        let end_l2_height = sequencer_commitment.l2_end_block_number;
        // Check if this commitment advances the chain state
        // We only accept strictly increasing heights and indices
        if let Some(committed_height) = self
            .ledger_db
            .get_highest_l2_height_for_status(L2HeightStatus::Committed, None)?
        {
            // Discard if the commitment doesn't advance L2 height
            if end_l2_height <= committed_height.height {
                info!(
                    "Skipping sequencer commitment with height {end_l2_height} as it is not strictly superior to existing commitment with height {}",
                    committed_height.height,
                );
                return Ok(ProcessingResult::Discarded);
            }

            // Discard if the commitment index isn't increasing
            if sequencer_commitment.index <= committed_height.commitment_index {
                info!(
                    "Skipping sequencer commitment with index {} as it is not strictly superior to the existing committed one",
                    sequencer_commitment.index,
                );
                return Ok(ProcessingResult::Discarded);
            }
        }

        fn insert_pending_commitment_if_not_exists<DB: NodeLedgerOps>(
            ledger_db: &DB,
            sequencer_commitment: &SequencerCommitment,
            found_in_l1_block_height: u64,
        ) -> Result<(), anyhow::Error> {
            let index = sequencer_commitment.index;
            if let Some((existing_commitment, _)) =
                ledger_db.get_pending_commitment_by_index(index)?
            {
                // Conflicting commitments are discarded at the top of `process_sequencer_commitment`,
                // so anything reaching here matches what is already pending
                assert!(
                    existing_commitment == *sequencer_commitment,
                    "Found a conflicting pending commitment on index {index}\nDA: {sequencer_commitment:?}\nDB:{existing_commitment:?}"
                );
            } else {
                ledger_db.store_pending_commitment(
                    sequencer_commitment.clone(),
                    found_in_l1_block_height,
                )?;
            }
            Ok(())
        }

        // Determine the starting L2 height for this commitment
        // For first commitment (index 1), start at Tangerine fork height
        // Otherwise, start at previous commitment's end height + 1
        let start_l2_height = if sequencer_commitment.index == 1 {
            get_tangerine_activation_height_non_zero()
        } else {
            match self
                .ledger_db
                .get_commitment_by_index(sequencer_commitment.index - 1)?
            {
                Some(previous_commitment) => previous_commitment.l2_end_block_number + 1,
                None => {
                    // If previous commitment is missing, store this one as pending
                    info!(
                            "Commitment with index {} is missing its predecessor (index {}). Storing as pending.",
                            sequencer_commitment.index,
                            sequencer_commitment.index - 1
                        );
                    insert_pending_commitment_if_not_exists(
                        &self.ledger_db,
                        sequencer_commitment,
                        found_in_l1_block_height,
                    )?;
                    return Ok(ProcessingResult::Pending);
                }
            }
        };

        info!(
            "Processing sequencer commitment for L2 Range = {}-{} at L1 height {}.",
            start_l2_height, end_l2_height, found_in_l1_block_height,
        );

        // Check if we have synced all L2 blocks needed for this commitment
        let head_l2_height = self
            .ledger_db
            .get_head_l2_block_height()?
            .unwrap_or_default();
        if end_l2_height > head_l2_height {
            info!(
                "Commitment with index: {} L2 blocks not synced yet. Range: {}-{}, merkle root: {} Storing commitment as pending.",
                sequencer_commitment.index,
                start_l2_height,
                end_l2_height,
                hex::encode(sequencer_commitment.merkle_root)
            );
            insert_pending_commitment_if_not_exists(
                &self.ledger_db,
                sequencer_commitment,
                found_in_l1_block_height,
            )?;
            return Ok(ProcessingResult::Pending);
        }

        // Verify the merkle root matches the L2 blocks
        // This ensures the commitment correctly represents the L2 chain
        let stored_l2_blocks: Vec<StoredL2Block> = self
            .ledger_db
            .get_l2_block_range(&(L2BlockNumber(start_l2_height)..=L2BlockNumber(end_l2_height)))?;

        let l2_blocks_tree = MerkleTree::<Sha256>::from_leaves(
            stored_l2_blocks
                .iter()
                .map(|x| x.hash)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        // Halt processing if merkle root doesn't match
        if l2_blocks_tree.root() != Some(sequencer_commitment.merkle_root) {
            return Err(
                HaltingError::Commitment(CommitmentError::MerkleRootMismatch(format!(
                    "Merkle root mismatch - expected 0x{} but got 0x{}. Skipping commitment.",
                    hex::encode(
                        l2_blocks_tree
                            .root()
                            .ok_or(anyhow!("Could not calculate l2 block tree root"))?
                    ),
                    hex::encode(sequencer_commitment.merkle_root)
                )))
                .into(),
            );
        }

        // Store the commitment and update all related state
        self.ledger_db.update_commitments_on_da_slot(
            found_in_l1_block_height,
            sequencer_commitment.clone(),
        )?;

        self.ledger_db.set_l2_range_by_commitment_merkle_root(
            sequencer_commitment.merkle_root,
            (L2BlockNumber(start_l2_height), L2BlockNumber(end_l2_height)),
        )?;

        self.ledger_db
            .put_commitment_by_index(sequencer_commitment)?;

        // Update the highest committed L2 height
        self.ledger_db.set_l2_height_status(
            L2HeightStatus::Committed,
            current_l1_block_height,
            L2HeightAndIndex {
                height: end_l2_height,
                commitment_index: sequencer_commitment.index,
            },
        )?;

        FM.highest_committed_l2_height.set(end_l2_height as f64);
        FM.highest_committed_index
            .set(sequencer_commitment.index as f64);

        Ok(ProcessingResult::Success)
    }

    /// Processes a ZK proof found in an L1 block
    ///
    /// This method handles the verification and processing of zero-knowledge proofs that validate
    /// L2 block execution. Each proof demonstrates the correctness of state transitions for a batch
    /// of L2 blocks. The method:
    /// 1. Extracts historical RISC0 outputs, trusting the prover's DA signature through L0,
    ///    or extracts and verifies later proofs against Pomelo's code commitment.
    /// 2. Processes the output using Tangerine-specific validation logic.
    ///
    /// DA extraction authenticates proofs before this method is called. Pending retries
    /// use the original publication height to select the same verification policy.
    ///
    /// # Arguments
    /// * `current_l1_block_height` - Current L1 block being processed
    /// * `found_in_l1_block_height` - L1 block where proof was found
    /// * `proof` - The ZK proof to process
    /// * `proof_source` - Whether the proof came from L1 or pending retries
    ///
    /// # Returns
    /// The processing result indicating:
    /// - Success: Proof was valid and processed
    /// - Discarded: Proof was redundant or for already proven blocks
    /// - Pending: Proof needs prerequisites before processing
    async fn process_zk_proof(
        &self,
        current_l1_block_height: u64,
        found_in_l1_block_height: u64,
        proof: Proof,
        proof_source: ProofSource,
    ) -> Result<ProcessingResult, ProcessingError> {
        tracing::info!(
            "Processing zk proof at height: {}",
            found_in_l1_block_height
        );
        tracing::trace!("ZK proof: {:?}", proof);

        let batch_proof_output = match self.risc0_cutoff_l1_height {
            // Proofs up to L0 are RISC0 proofs, they are accepted on the batch prover's DA signature
            // To verify them, run v2 up to L0 and then update to v3
            Some(l0) if found_in_l1_block_height <= l0 => {
                let Some(batch_proof_output) = crate::risc0_proof::extract_batch_proof_output(
                    &proof,
                    network_to_dev_mode(self.network),
                ) else {
                    tracing::warn!(
                        "Discarding RISC0 proof at L1 height {found_in_l1_block_height}: its receipt can't be read"
                    );
                    return Ok(ProcessingResult::Discarded);
                };
                batch_proof_output
            }
            _ => {
                // Extract and verify the proof using the appropriate ZKVM
                let Ok(batch_proof_output) = Vm::extract_output::<BatchProofCircuitOutput>(&proof)
                else {
                    return Ok(ProcessingResult::Discarded);
                };

                let code_commitment = self
                    .code_commitments_by_spec
                    .get(&proof_guest_spec_id())
                    .expect("Proof guest spec must have a code commitment");

                // Verify the proof against the code commitment
                if Vm::verify(
                    proof.as_slice(),
                    code_commitment,
                    network_to_dev_mode(self.network),
                )
                .is_err()
                {
                    return Ok(ProcessingResult::Discarded);
                }
                batch_proof_output
            }
        };

        tracing::info!(
            "Extracted batch proof output with last L2 height: {}, commitment index range: {}-{}",
            batch_proof_output.last_l2_height(),
            batch_proof_output.sequencer_commitment_index_range().0,
            batch_proof_output.sequencer_commitment_index_range().1
        );

        // Process the verified proof using Tangerine-specific logic
        self.process_tangerine_zk_proof(
            current_l1_block_height,
            found_in_l1_block_height,
            batch_proof_output.initial_state_root(),
            proof,
            batch_proof_output,
            proof_source,
        )
        .await
    }

    /// Processes a Tangerine-specific ZK proof
    ///
    /// # Arguments
    /// * `current_l1_block_height` - Current L1 block being processed
    /// * `found_in_l1_block_height` - L1 block where proof was found
    /// * `initial_state_root` - Initial state root for verification
    /// * `raw_proof` - The raw ZK proof
    /// * `batch_proof_output` - The batch proof circuit output
    /// * `proof_source` - Whether the proof came from L1 or pending retries
    ///
    /// # Returns
    /// The processing result indicating success, discard, or pending status
    async fn process_tangerine_zk_proof(
        &self,
        current_l1_block_height: u64,
        found_in_l1_block_height: u64,
        initial_state_root: [u8; 32],
        raw_proof: Proof,
        batch_proof_output: BatchProofCircuitOutput,
        proof_source: ProofSource,
    ) -> Result<ProcessingResult, ProcessingError> {
        let last_l1_hash_on_bitcoin_light_client_contract =
            batch_proof_output.last_l1_hash_on_bitcoin_light_client_contract();
        if self
            .ledger_db
            .get_l1_height_of_l1_hash(last_l1_hash_on_bitcoin_light_client_contract)?
            .is_none()
        {
            return Err(SkippableError::Proof(ProofError::UnknownL1Hash).into());
        }

        let sequencer_commitment_index_range =
            batch_proof_output.sequencer_commitment_index_range();
        let commitments_hashes = batch_proof_output.sequencer_commitment_hashes();

        // The proof's commitment index range must be ascending and cover exactly as many
        // commitments as it carries hashes. The light client circuit enforces both
        // (`crates/light-client-prover/src/circuit/mod.rs`); without the same checks here the
        // zip below would silently drop trailing hashes, so the full node would accept - and
        // mark proven - a proof the light client rejects.
        if sequencer_commitment_index_range.1 < sequencer_commitment_index_range.0 {
            return Err(
                SkippableError::Proof(ProofError::InvalidCommitmentIndexRange(
                    sequencer_commitment_index_range.0,
                    sequencer_commitment_index_range.1,
                ))
                .into(),
            );
        }
        let index_range_len =
            (sequencer_commitment_index_range.1 - sequencer_commitment_index_range.0) as usize + 1;
        if index_range_len != commitments_hashes.len() {
            return Err(
                SkippableError::Proof(ProofError::CommitmentIndexRangeHashCountMismatch(
                    sequencer_commitment_index_range.0,
                    sequencer_commitment_index_range.1,
                    index_range_len,
                    commitments_hashes.len(),
                ))
                .into(),
            );
        }

        let proven_height = self
            .ledger_db
            .get_highest_l2_height_for_status(L2HeightStatus::Proven, None)?
            .unwrap_or_default();

        let end_l2_height = batch_proof_output.last_l2_height();

        if end_l2_height <= proven_height.height
            || sequencer_commitment_index_range.1 <= proven_height.commitment_index
        {
            tracing::info!(
                "Skipping proof with height {} and index {} as we already have proof with height {} and index {}",
                end_l2_height,
                sequencer_commitment_index_range.1,
                proven_height.height,
                proven_height.commitment_index
            );
            return Ok(ProcessingResult::Discarded);
        }

        let committed_height = self
            .ledger_db
            .get_highest_l2_height_for_status(L2HeightStatus::Committed, None)?
            .unwrap_or_default();

        if proven_height > committed_height {
            panic!("Proven height {proven_height:?} above committed height {committed_height:?}");
        }
        let mut proof_is_pending = false;
        // make sure init roots match <- TODO: with proposed changes in issues this will be unnecessary
        let previous_l2_end_block_number = match batch_proof_output.previous_commitment_index() {
            Some(idx) => {
                self.verify_sequencer_commitment_hash_by_index(
                    idx,
                    batch_proof_output.previous_commitment_hash().expect("If previous commitment index is present, then the previous commitment hash must be present too"),
                    &mut proof_is_pending,
                )?
            }
            // If there is no previous seq comm hash then this must be the first post tangerine commitment
            None => get_tangerine_activation_height_non_zero() - 1,
        };

        let mut last_commitment_l2_end_height = None;
        for (index, expected_hash) in (sequencer_commitment_index_range.0
            ..=sequencer_commitment_index_range.1)
            .zip(commitments_hashes)
        {
            last_commitment_l2_end_height = Some(self.verify_sequencer_commitment_hash_by_index(
                index,
                expected_hash,
                &mut proof_is_pending,
            )?);
        }

        let last_commitment_l2_end_height =
            last_commitment_l2_end_height.expect("Sequencer commitment index range is non-empty");

        // The proof's terminal L2 height must be the L2 end height of the last commitment it
        // covers
        if end_l2_height != last_commitment_l2_end_height {
            return Err(SkippableError::Proof(ProofError::LastL2HeightMismatch(
                end_l2_height,
                sequencer_commitment_index_range.1,
                last_commitment_l2_end_height,
            ))
            .into());
        }

        if proof_is_pending {
            if proof_source == ProofSource::FromL1 {
                info!(
                    "Proof is pending for commitment index range {}-{}. Storing proof as pending.",
                    sequencer_commitment_index_range.0, sequencer_commitment_index_range.1
                );
                self.ledger_db.store_pending_proof(
                    sequencer_commitment_index_range.0,
                    sequencer_commitment_index_range.1,
                    raw_proof,
                    found_in_l1_block_height,
                )?;
            } else {
                info!(
                    "Proof is pending for commitment index range {}-{}. Keeping existing pending proof without rewrite.",
                    sequencer_commitment_index_range.0, sequencer_commitment_index_range.1
                );
            }
            return Ok(ProcessingResult::Pending);
        }

        // Check that first commitment's state root matches initial_state_root
        let start_state_root = self
                .ledger_db
                .get_l2_state_root(previous_l2_end_block_number)?
                .ok_or_else(|| {
                    anyhow!(
                        "Proof verification: Could not find state root for L2 height: {previous_l2_end_block_number}. Skipping proof."
                    )
                })?;

        if start_state_root != initial_state_root {
            return Err(SkippableError::Proof(ProofError::PreStateRootMismatch(
                hex::encode(initial_state_root),
                hex::encode(start_state_root),
            ))
            .into());
        }

        if sequencer_commitment_index_range.0 > proven_height.commitment_index + 1 {
            if proof_source == ProofSource::FromL1 {
                info!(
                    "First commitment in range is not strictly increasing. Expected index {}, got {}. Storing proof as pending for commitment range {}-{}",
                    proven_height.commitment_index + 1,
                    sequencer_commitment_index_range.0,
                    sequencer_commitment_index_range.0,
                    sequencer_commitment_index_range.1
                );
                self.ledger_db.store_pending_proof(
                    sequencer_commitment_index_range.0,
                    sequencer_commitment_index_range.1,
                    raw_proof,
                    found_in_l1_block_height,
                )?;
            } else {
                info!(
                    "First commitment in range is not strictly increasing. Expected index {}, got {}. Keeping existing pending proof for commitment range {}-{} without rewrite",
                    proven_height.commitment_index + 1,
                    sequencer_commitment_index_range.0,
                    sequencer_commitment_index_range.0,
                    sequencer_commitment_index_range.1
                );
            }
            return Ok(ProcessingResult::Pending);
        }

        // store in ledger db
        self.ledger_db.update_verified_proof_data(
            found_in_l1_block_height,
            raw_proof,
            batch_proof_output.into(),
        )?;

        self.ledger_db.set_l2_height_status(
            L2HeightStatus::Proven,
            current_l1_block_height,
            L2HeightAndIndex {
                height: end_l2_height,
                commitment_index: sequencer_commitment_index_range.1,
            },
        )?;

        FM.highest_proven_l2_height.set(end_l2_height as f64);

        Ok(ProcessingResult::Success)
    }

    /// Processes any pending commitments up to the current L1 block height
    ///
    /// This method attempts to process commitments that were previously stored as pending because
    /// their prerequisites weren't met. A commitment might be pending because:
    /// - Its previous commitment wasn't processed yet
    /// - The L2 blocks it commits to weren't synced yet
    ///
    /// The method processes pending commitments in order by index, since each commitment must build
    /// on the previous one. Processing stops at the first commitment that still can't be processed,
    /// as all later commitments will also be unprocessable.
    ///
    /// This is a crucial part of maintaining the chain's commitment order and ensuring no gaps in
    /// the sequence of committed L2 blocks.
    ///
    /// # Arguments
    /// * `current_l1_block_height` - Current L1 block being processed
    ///
    /// # Returns
    /// Success if all processable pending commitments were handled, or an error if processing failed
    async fn process_pending_commitments(
        &self,
        current_l1_block_height: u64,
    ) -> Result<(), ProcessingError> {
        let pending_commitments = self.ledger_db.get_pending_commitments()?;

        // Try to process each pending commitment in order
        for item in pending_commitments {
            let (index, (commitment, found_in_l1_height)) = item?.into_tuple();
            // A commitment is processable if:
            // - For index 1: all its L2 blocks are synced
            // - For other indices: its previous commitment exists
            let processable = if index == 1 {
                let head_l2_height = self
                    .ledger_db
                    .get_head_l2_block_height()?
                    .unwrap_or_default();
                let end_l2_height = commitment.l2_end_block_number;
                end_l2_height <= head_l2_height
            } else {
                self.ledger_db.get_commitment_by_index(index - 1)?.is_some()
            };

            if processable {
                // Try to process the commitment now that dependencies are met
                match self
                    .process_sequencer_commitment(
                        current_l1_block_height,
                        found_in_l1_height,
                        &commitment,
                    )
                    .await
                {
                    Err(e) => match e {
                        ProcessingError::HaltingError(HaltingError::Commitment(e)) => {
                            error!(
                                "Halting error while processing pending commitment with index {index}: {e:?}"
                            );
                            return Err(HaltingError::Commitment(e).into());
                        }
                        _ => {
                            warn!("Failed to process pending commitment with index {index}: {e:?}");
                            break;
                        }
                    },
                    Ok(ProcessingResult::Success) => {
                        info!("Successfully processed pending commitment {index}");
                        self.ledger_db.remove_pending_commitment(index)?;
                    }
                    Ok(ProcessingResult::Discarded) => {
                        info!("Discarding pending commitment {index}");
                        self.ledger_db.remove_pending_commitment(index)?;
                    }
                    Ok(ProcessingResult::Pending) => {
                        debug!("Keeping commitment {index} as pending")
                    }
                }
            } else {
                // Stop processing since remaining commitments will also be unprocessable
                // (pending commitments are sorted by index)
                break;
            }
        }

        Ok(())
    }

    /// Processes any pending proofs up to the current L1 block height
    ///
    /// This method attempts to process proofs that were previously pending
    /// due to missing dependencies.
    async fn process_pending_proofs(
        &self,
        current_l1_block_height: u64,
    ) -> Result<(), ProcessingError> {
        let pending_proofs = self.ledger_db.get_pending_proofs()?;

        for item in pending_proofs {
            let ((min_index, max_index), (proof, found_in_l1_height)) = item?.into_tuple();
            match self
                .process_zk_proof(
                    current_l1_block_height,
                    found_in_l1_height,
                    proof,
                    ProofSource::FromPendingRetry,
                )
                .await
            {
                Err(e) => {
                    warn!(
                        "Failed to process pending proof with index {min_index}-{max_index}: {e:?}"
                    );
                    match e {
                        ProcessingError::HaltingError(HaltingError::Proof(e)) => {
                            return Err(HaltingError::Proof(e).into());
                        }
                        ProcessingError::SkippableError(SkippableError::Proof(_)) => {
                            self.ledger_db.remove_pending_proof(min_index, max_index)?;
                        }
                        ProcessingError::Other(_) => {
                            // Stop processing further pending proofs as they may depend on this one
                            break;
                        }
                        _ => {
                            unreachable!(
                                "Unexpected error type while processing pending proof: {e:?}"
                            );
                        }
                    }
                }
                Ok(ProcessingResult::Success) => {
                    info!("Successfully processed pending proof for commitment index range {min_index}-{max_index}");
                    self.ledger_db.remove_pending_proof(min_index, max_index)?;
                }
                Ok(ProcessingResult::Discarded) => {
                    info!("Discarding pending proof for commitment index range {min_index}-{max_index}");
                    self.ledger_db.remove_pending_proof(min_index, max_index)?;
                }
                Ok(ProcessingResult::Pending) => {
                    debug!("Keeping proof over commitment index range {min_index}-{max_index} as pending");
                    // Proofs are sorted by min_index.
                    // We can break on the first pending proof as subsequent ones will depend on it and should be kept as pending
                    break;
                }
            }
        }

        Ok(())
    }

    /// Verifies a sequencer commitment hash at a specific index
    ///
    /// # Arguments
    /// * `idx` - Index of the commitment to verify
    /// * `expected_hash` - Expected commitment hash
    /// * `proof_is_pending` - Out parameter indicating if verification is pending
    ///
    /// # Returns
    /// The L2 end block number of the commitment
    fn verify_sequencer_commitment_hash_by_index(
        &self,
        idx: u32,
        expected_hash: [u8; 32],
        proof_is_pending: &mut bool,
    ) -> Result<u64, ProcessingError> {
        let sequencer_commitment = if let Some(sequencer_commitment) =
            self.ledger_db.get_commitment_by_index(idx)?
        {
            sequencer_commitment
        } else if let Some((sequencer_commitment, _)) =
            self.ledger_db.get_pending_commitment_by_index(idx)?
        {
            // If we have a pending commitment, we need to store the proof as pending
            info!("Proof has a pending commitment with index: {}.", idx);
            *proof_is_pending = true;
            sequencer_commitment
        } else {
            return Err(
                SkippableError::Proof(ProofError::SequencerCommitmentMissingForProof(idx)).into(),
            );
        };

        // Check if hash matches
        if sequencer_commitment.serialize_and_calculate_sha_256() != expected_hash {
            return Err(
                SkippableError::Proof(ProofError::SequencerCommitmentHashMismatch(
                    hex::encode(sequencer_commitment.serialize_and_calculate_sha_256()),
                    hex::encode(expected_hash),
                ))
                .into(),
            );
        }
        Ok(sequencer_commitment.l2_end_block_number)
    }
}

#[cfg(test)]
mod tests {
    use citrea_common::backup::BackupManager;
    use citrea_common::NodeType;
    use citrea_primitives::forks::FORKS;
    use sov_db::ledger_db::migrations::LedgerMigration;
    use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
    use sov_db::rocks_db_config::RocksdbConfig;
    use sov_db::schema::tables::FULL_NODE_LEDGER_TABLES;
    use sov_mock_da::{MockAddress, MockDaService};
    use sov_mock_zkvm::MockZkvm;
    use sov_modules_api::fork::Fork;
    use sov_modules_api::L2Block;
    use sov_rollup_interface::block::{L2Header, SignedL2Header};
    use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
    use tempfile::TempDir;

    use super::*;
    use crate::db_migrations::RescanL1AfterRisc0Cutoff;

    /// Forks used by the tests in this module. Mirrors `NIGHTLY_FORKS`.
    const TEST_FORKS: &[Fork] = &[Fork::new(SpecId::Pomelo, 0)];

    /// L1 hash the crafted proof outputs claim to end on.
    const L1_HASH: [u8; 32] = [0xaa; 32];
    /// L1 height at which the proof is found and processed.
    const L1_HEIGHT: u64 = 42;

    /// A full node ledger DB plus the L1 block handler operating on it.
    struct TestNode {
        /// Handler under test.
        handler: L1BlockHandler<MockZkvm, MockDaService, LedgerDB>,
        /// Handle on the same ledger DB the handler writes to.
        ledger_db: LedgerDB,
        /// Keeps the temporary directory backing the DBs alive.
        _tmpdir: TempDir,
    }

    /// Builds an [`L1BlockHandler`] backed by a temporary full node ledger DB.
    fn setup() -> TestNode {
        let _ = FORKS.set(TEST_FORKS);

        let tmpdir = TempDir::new().unwrap();
        let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(
            tmpdir.path(),
            None,
            Some(
                FULL_NODE_LEDGER_TABLES
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            ),
        ))
        .unwrap();
        let da_service = Arc::new(MockDaService::new(
            MockAddress::from([1; 32]),
            tmpdir.path(),
        ));

        let handler = L1BlockHandler::new(
            Network::Nightly,
            ledger_db.clone(),
            da_service,
            vec![1; 33],
            vec![2; 33],
            HashMap::new(),
            Arc::new(Mutex::new(L1BlockCache::new())),
            Arc::new(BackupManager::new(NodeType::FullNode, None, None)),
            None,
        );

        TestNode {
            handler,
            ledger_db,
            _tmpdir: tmpdir,
        }
    }

    /// Historical receipt with a readable journal but no valid ZK seal.
    fn historical_risc0_proof() -> Proof {
        hex::decode(include_str!("../test_data/risc0-groth16-receipt.hex").trim()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn historical_risc0_proofs_trust_signature_but_still_validate_output() {
        let TestNode {
            mut handler,
            _tmpdir,
            ..
        } = setup();
        handler.risc0_cutoff_l1_height = Some(L1_HEIGHT);

        for found_at in [L1_HEIGHT - 1, L1_HEIGHT] {
            for source in [ProofSource::FromL1, ProofSource::FromPendingRetry] {
                let result = handler
                    .process_zk_proof(L1_HEIGHT + 1, found_at, historical_risc0_proof(), source)
                    .await;
                // Reaching output validation proves that the historical receipt was
                // extracted without VM verification, even when retried after L0.
                assert!(matches!(
                    result,
                    Err(ProcessingError::SkippableError(SkippableError::Proof(
                        ProofError::UnknownL1Hash
                    )))
                ));
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn risc0_proofs_are_discarded_after_cutoff_or_without_one() {
        let TestNode {
            mut handler,
            _tmpdir,
            ..
        } = setup();
        for (cutoff, found_at) in [(Some(L1_HEIGHT), L1_HEIGHT + 1), (None, L1_HEIGHT)] {
            handler.risc0_cutoff_l1_height = cutoff;
            let result = handler
                .process_zk_proof(
                    L1_HEIGHT + 1,
                    found_at,
                    historical_risc0_proof(),
                    ProofSource::FromL1,
                )
                .await
                .unwrap();
            assert!(matches!(result, ProcessingResult::Discarded));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn post_cutoff_proofs_still_require_vm_verification() {
        let TestNode {
            mut handler,
            _tmpdir,
            ..
        } = setup();
        handler
            .code_commitments_by_spec
            .insert(SpecId::Pomelo, sov_mock_zkvm::MockCodeCommitment([0; 32]));
        let output =
            crate::risc0_proof::extract_batch_proof_output(&historical_risc0_proof(), false)
                .unwrap();
        // This has the mock host's readable output format, but is not a valid proof.
        let proof = borsh::to_vec(&(borsh::to_vec(&output).unwrap(), false)).unwrap();
        assert!(<MockZkvm as ZkvmHost>::extract_output::<BatchProofCircuitOutput>(&proof).is_ok());

        for (cutoff, found_at) in [(Some(L1_HEIGHT), L1_HEIGHT + 1), (None, L1_HEIGHT)] {
            handler.risc0_cutoff_l1_height = cutoff;
            let result = handler
                .process_zk_proof(L1_HEIGHT + 1, found_at, proof.clone(), ProofSource::FromL1)
                .await
                .unwrap();
            assert!(matches!(result, ProcessingResult::Discarded));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_historical_risc0_proofs_are_discarded() {
        let TestNode {
            mut handler,
            _tmpdir,
            ..
        } = setup();
        handler.risc0_cutoff_l1_height = Some(L1_HEIGHT);
        let mut proof = historical_risc0_proof();
        proof.pop();
        let result = handler
            .process_zk_proof(L1_HEIGHT, L1_HEIGHT, proof, ProofSource::FromL1)
            .await
            .unwrap();
        assert!(matches!(result, ProcessingResult::Discarded));
    }

    /// Historical receipt like [`historical_risc0_proof`] whose journal is `output`.
    fn risc0_proof_with_output(output: &BatchProofCircuitOutput) -> Proof {
        let receipt = historical_risc0_proof();
        // bincode encodes the journal with its length as u64
        let encode = |journal: Vec<u8>| [(journal.len() as u64).to_le_bytes().to_vec(), journal];
        let fixture_output =
            crate::risc0_proof::extract_batch_proof_output(&receipt, false).unwrap();
        let old = encode(borsh::to_vec(&fixture_output).unwrap()).concat();
        let at = receipt
            .windows(old.len())
            .position(|window| window == old)
            .unwrap();
        let new = encode(borsh::to_vec(output).unwrap()).concat();
        let proof = [&receipt[..at], &new, &receipt[at + old.len()..]].concat();
        let extracted = crate::risc0_proof::extract_batch_proof_output(&proof, false).unwrap();
        assert_eq!(
            borsh::to_vec(&extracted).unwrap(),
            borsh::to_vec(output).unwrap()
        );
        proof
    }

    /// RISC0 proofs published up to L0 advance the proven height on the batch prover's DA
    /// signature, but only with a valid output. RISC0 proving stops at P0, and a RISC0 proof
    /// published after L0 anyway is discarded without stalling the full node. SP1 proofs
    /// continue from P0.
    #[tokio::test(flavor = "multi_thread")]
    async fn proven_height_continues_from_risc0_proofs_to_sp1_proofs() {
        let TestNode {
            mut handler,
            ledger_db,
            _tmpdir,
        } = setup();
        handler.risc0_cutoff_l1_height = Some(L1_HEIGHT);
        let (commitment_1, commitment_2) = seed_canonical_chain(&ledger_db);
        let commitment_3 = commitment(3, 3);
        put_l2_block(&ledger_db, 3);
        ledger_db.put_commitment_by_index(&commitment_3).unwrap();
        ledger_db
            .set_l2_height_status(
                L2HeightStatus::Committed,
                L1_HEIGHT - 1,
                L2HeightAndIndex {
                    height: 3,
                    commitment_index: 3,
                },
            )
            .unwrap();
        let proven = || {
            let proven = ledger_db
                .get_highest_l2_height_for_status(L2HeightStatus::Proven, None)
                .unwrap()
                .unwrap();
            (proven.height, proven.commitment_index)
        };

        let output_2 = proof_output(
            (2, 2),
            vec![commitment_2.serialize_and_calculate_sha_256()],
            2,
            &commitment_1,
        );
        let output_3 = proof_output(
            (3, 3),
            vec![commitment_3.serialize_and_calculate_sha_256()],
            3,
            &commitment_2,
        );
        let BatchProofCircuitOutput::V3(mut wrong_pre_state) = proof_output(
            (2, 2),
            vec![commitment_2.serialize_and_calculate_sha_256()],
            2,
            &commitment_1,
        );
        wrong_pre_state.state_roots[0] = [0xbb; 32];
        let wrong_pre_state = BatchProofCircuitOutput::V3(wrong_pre_state);

        // A historical proof with an output that doesn't match the chain is rejected
        let result = handler
            .process_zk_proof(
                L1_HEIGHT,
                L1_HEIGHT,
                risc0_proof_with_output(&wrong_pre_state),
                ProofSource::FromL1,
            )
            .await;
        assert!(matches!(
            result,
            Err(ProcessingError::SkippableError(SkippableError::Proof(
                ProofError::PreStateRootMismatch(..)
            )))
        ));
        assert_eq!(proven(), (1, 1));

        // A historical proof at L0 is accepted without VM verification
        let result = handler
            .process_zk_proof(
                L1_HEIGHT,
                L1_HEIGHT,
                risc0_proof_with_output(&output_2),
                ProofSource::FromL1,
            )
            .await
            .unwrap();
        assert!(matches!(result, ProcessingResult::Success));
        assert_eq!(proven(), (2, 2));

        // A RISC0 proof of the next commitment, published after L0 anyway, is discarded
        let result = handler
            .process_zk_proof(
                L1_HEIGHT + 1,
                L1_HEIGHT + 1,
                risc0_proof_with_output(&output_3),
                ProofSource::FromL1,
            )
            .await
            .unwrap();
        assert!(matches!(result, ProcessingResult::Discarded));
        assert_eq!(proven(), (2, 2));

        // The verified SP1 proof of the same commitment continues from P0
        let result = handler
            .process_tangerine_zk_proof(
                L1_HEIGHT + 1,
                L1_HEIGHT + 1,
                state_root(commitment_2.l2_end_block_number),
                vec![],
                output_3,
                ProofSource::FromL1,
            )
            .await
            .unwrap();
        assert!(matches!(result, ProcessingResult::Success));
        assert_eq!(proven(), (3, 3));
    }

    /// Writes `status` at `l1_height` for commitment `index`, which ends at L2 height `index`.
    fn set_status(ledger_db: &LedgerDB, status: L2HeightStatus, l1_height: u64, index: u32) {
        ledger_db
            .set_l2_height_status(
                status,
                l1_height,
                L2HeightAndIndex {
                    height: index.into(),
                    commitment_index: index,
                },
            )
            .unwrap();
    }

    /// The status the node reads, as L2 height and commitment index.
    fn highest(ledger_db: &LedgerDB, status: L2HeightStatus) -> (u64, u32) {
        let row = ledger_db
            .get_highest_l2_height_for_status(status, None)
            .unwrap()
            .unwrap();
        (row.height, row.commitment_index)
    }

    /// v2 committed commitment 2 late, while processing `v2_last`, and stopped with commitment
    /// 3 pending until its L2 blocks were synced. The rescan from L0 commits it at an earlier L1
    /// height, and v2's row doesn't hide it. Otherwise a proof covering commitment 3 would put
    /// the proven height above the committed one, and the next proof would panic.
    #[tokio::test(flavor = "multi_thread")]
    async fn rescan_from_l0_commits_past_late_v2_committed_row() {
        let TestNode {
            handler,
            ledger_db,
            _tmpdir,
        } = setup();
        seed_canonical_chain(&ledger_db);
        set_status(&ledger_db, L2HeightStatus::Committed, L1_HEIGHT + 10, 2);

        let commitment_3 = commitment(3, 3);
        put_l2_block(&ledger_db, 3);
        let result = handler
            .process_sequencer_commitment(L1_HEIGHT + 1, L1_HEIGHT + 1, &commitment_3)
            .await
            .unwrap();
        assert!(matches!(result, ProcessingResult::Success));
        assert_eq!(highest(&ledger_db, L2HeightStatus::Committed), (3, 3));
    }

    /// The stall from the PR 81 thread, on a v2 node upgraded late. v2 accepted the proof of
    /// commitment 2, published up to L0, only while processing `v2_last`, and walked past the
    /// SP1 proofs after it. The migration moves the scan back to L0 and keeps that row, and the
    /// SP1 proofs the rescan reads at earlier L1 heights advance the proven height past it.
    #[tokio::test(flavor = "multi_thread")]
    async fn rescan_from_l0_advances_past_late_v2_proven_row() {
        let TestNode {
            handler,
            ledger_db,
            _tmpdir,
        } = setup();
        let (_, commitment_2) = seed_canonical_chain(&ledger_db);
        let commitment_3 = commitment(3, 3);
        let commitment_4 = commitment(4, 4);
        for commitment in [&commitment_3, &commitment_4] {
            put_l2_block(&ledger_db, commitment.l2_end_block_number);
            ledger_db.put_commitment_by_index(commitment).unwrap();
        }
        let l0 = L1_HEIGHT;
        let v2_last = l0 + 10;
        set_status(&ledger_db, L2HeightStatus::Committed, v2_last, 4);
        set_status(&ledger_db, L2HeightStatus::Proven, v2_last, 2);
        ledger_db
            .set_last_scanned_l1_height(SlotNumber(v2_last + 10))
            .unwrap();

        RescanL1AfterRisc0Cutoff { l0 }
            .execute(Arc::new(ledger_db.clone()), &mut Vec::new())
            .unwrap();
        assert_eq!(
            ledger_db
                .get_last_scanned_l1_height()
                .unwrap()
                .map(|height| height.0),
            Some(l0)
        );
        assert_eq!(highest(&ledger_db, L2HeightStatus::Proven), (2, 2));

        for (l1_height, previous, commitment) in [
            (l0 + 1, &commitment_2, &commitment_3),
            (l0 + 2, &commitment_3, &commitment_4),
        ] {
            let output = proof_output(
                (commitment.index, commitment.index),
                vec![commitment.serialize_and_calculate_sha_256()],
                commitment.l2_end_block_number,
                previous,
            );
            let result = handler
                .process_tangerine_zk_proof(
                    l1_height,
                    l1_height,
                    state_root(previous.l2_end_block_number),
                    vec![],
                    output,
                    ProofSource::FromL1,
                )
                .await
                .unwrap();
            assert!(matches!(result, ProcessingResult::Success));
            assert_eq!(
                highest(&ledger_db, L2HeightStatus::Proven),
                (commitment.l2_end_block_number, commitment.index)
            );
        }
    }

    /// Builds a sequencer commitment with a deterministic merkle root.
    fn commitment(index: u32, l2_end_block_number: u64) -> SequencerCommitment {
        SequencerCommitment {
            merkle_root: [index as u8; 32],
            index,
            l2_end_block_number,
        }
    }

    /// Deterministic state root for a given L2 height.
    fn state_root(height: u64) -> [u8; 32] {
        let mut root = [0u8; 32];
        root[0] = height as u8;
        root
    }

    /// Stores an L2 block carrying [`state_root`] for `height`.
    fn put_l2_block(ledger_db: &LedgerDB, height: u64) {
        let l2_block = L2Block::new(
            SignedL2Header::new(
                L2Header::new(height, [0; 32], state_root(height), 0, [0; 32], 0),
                [height as u8; 32],
                vec![],
            ),
            vec![],
        );
        ledger_db.commit_l2_block(l2_block, vec![], None).unwrap();
    }

    /// Builds a V3 batch proof output for the given commitments.
    ///
    /// `hashes` and `index_range` are passed separately so that tests can craft
    /// outputs an honest guest would never produce.
    fn proof_output(
        index_range: (u32, u32),
        hashes: Vec<[u8; 32]>,
        last_l2_height: u64,
        previous: &SequencerCommitment,
    ) -> BatchProofCircuitOutput {
        let mut state_roots = vec![state_root(previous.l2_end_block_number)];
        state_roots.extend((0..hashes.len()).map(|i| state_root(100 + i as u64)));

        BatchProofCircuitOutput::V3(BatchProofCircuitOutputV3 {
            state_roots,
            final_l2_block_hash: [0; 32],
            state_diff: Default::default(),
            last_l2_height,
            sequencer_commitment_hashes: hashes,
            sequencer_commitment_index_range: index_range,
            last_l1_hash_on_bitcoin_light_client_contract: L1_HASH,
            previous_commitment_index: Some(previous.index),
            previous_commitment_hash: Some(previous.serialize_and_calculate_sha_256()),
        })
    }

    /// Seeds the ledger with commitments 1 (ending at L2 height 1) and 2 (ending
    /// at L2 height 2), their L2 blocks, and the matching finality statuses:
    /// commitment 1 proven, commitment 2 committed but not yet proven.
    fn seed_canonical_chain(ledger_db: &LedgerDB) -> (SequencerCommitment, SequencerCommitment) {
        let commitment_1 = commitment(1, 1);
        let commitment_2 = commitment(2, 2);

        for height in 1..=2 {
            put_l2_block(ledger_db, height);
        }
        ledger_db.put_commitment_by_index(&commitment_1).unwrap();
        ledger_db.put_commitment_by_index(&commitment_2).unwrap();
        ledger_db.set_l1_height_of_l1_hash(L1_HASH, 1).unwrap();

        ledger_db
            .set_l2_height_status(
                L2HeightStatus::Proven,
                L1_HEIGHT - 1,
                L2HeightAndIndex {
                    height: 1,
                    commitment_index: 1,
                },
            )
            .unwrap();
        ledger_db
            .set_l2_height_status(
                L2HeightStatus::Committed,
                L1_HEIGHT - 1,
                L2HeightAndIndex {
                    height: 2,
                    commitment_index: 2,
                },
            )
            .unwrap();

        (commitment_1, commitment_2)
    }

    /// Sanity check for the harness: an honest proof covering exactly
    /// commitment 2 is accepted and advances the proven height to 2.
    #[tokio::test(flavor = "multi_thread")]
    async fn honest_proof_advances_proven_height() {
        let TestNode {
            handler, ledger_db, ..
        } = setup();
        let (commitment_1, commitment_2) = seed_canonical_chain(&ledger_db);

        let output = proof_output(
            (2, 2),
            vec![commitment_2.serialize_and_calculate_sha_256()],
            commitment_2.l2_end_block_number,
            &commitment_1,
        );

        let result = handler
            .process_tangerine_zk_proof(
                L1_HEIGHT,
                L1_HEIGHT,
                state_root(commitment_1.l2_end_block_number),
                vec![],
                output,
                ProofSource::FromL1,
            )
            .await
            .expect("honest proof must be accepted");
        assert!(matches!(result, ProcessingResult::Success));

        let proven = ledger_db
            .get_highest_l2_height_for_status(L2HeightStatus::Proven, None)
            .unwrap()
            .unwrap();
        assert_eq!(proven.height, 2);
        assert_eq!(proven.commitment_index, 2);
    }

    /// A batch proof whose commitment hash count exceeds the cardinality of its
    /// inclusive index range must be rejected.
    ///
    /// The guest builds the public index range from the first and last input
    /// commitments, so a prover feeding `{index: 2, end: 2}` (canonical) plus an
    /// extra `{index: 2, end: 3}` produces the range `(2, 2)` with two hashes.
    /// The light client circuit rejects this shape
    /// (`crates/light-client-prover/src/circuit/mod.rs`), but the full node zips
    /// the range against the hashes and silently drops the trailing hash.
    #[tokio::test(flavor = "multi_thread")]
    async fn proof_with_more_hashes_than_index_range_is_rejected() {
        let TestNode {
            handler, ledger_db, ..
        } = setup();
        let (commitment_1, commitment_2) = seed_canonical_chain(&ledger_db);

        // The extra commitment the malicious prover appends. It is never written
        // to the ledger DB: only its hash rides along in the proof output.
        let extra = commitment(2, 3);

        let output = proof_output(
            (2, 2),
            vec![
                commitment_2.serialize_and_calculate_sha_256(),
                extra.serialize_and_calculate_sha_256(),
            ],
            extra.l2_end_block_number,
            &commitment_1,
        );

        let result = handler
            .process_tangerine_zk_proof(
                L1_HEIGHT,
                L1_HEIGHT,
                state_root(commitment_1.l2_end_block_number),
                vec![],
                output,
                ProofSource::FromL1,
            )
            .await;

        assert!(
            result.is_err(),
            "proof output with 2 hashes over the inclusive range (2, 2) must not be accepted"
        );
    }

    /// Even if the above shape is accepted, the recorded proven height must never
    /// exceed the L2 end height of the last commitment the proof actually
    /// covers, nor the current committed height.
    ///
    /// Recording a higher proven height splits the full node from the light
    /// client (which rejects the proof) and reports `finalized` blocks that no
    /// verified proof covers. It also arms the
    /// `proven_height > committed_height` panic on the next proof.
    #[tokio::test(flavor = "multi_thread")]
    async fn duplicate_index_proof_does_not_advance_proven_height_past_committed() {
        let TestNode {
            handler, ledger_db, ..
        } = setup();
        let (commitment_1, commitment_2) = seed_canonical_chain(&ledger_db);

        let extra = commitment(2, 3);
        let output = proof_output(
            (2, 2),
            vec![
                commitment_2.serialize_and_calculate_sha_256(),
                extra.serialize_and_calculate_sha_256(),
            ],
            extra.l2_end_block_number,
            &commitment_1,
        );

        let _ = handler
            .process_tangerine_zk_proof(
                L1_HEIGHT,
                L1_HEIGHT,
                state_root(commitment_1.l2_end_block_number),
                vec![],
                output,
                ProofSource::FromL1,
            )
            .await;

        let proven = ledger_db
            .get_highest_l2_height_for_status(L2HeightStatus::Proven, None)
            .unwrap()
            .unwrap();
        let committed = ledger_db
            .get_highest_l2_height_for_status(L2HeightStatus::Committed, None)
            .unwrap()
            .unwrap();

        assert_eq!(
            commitment_2.l2_end_block_number, 2,
            "canonical commitment 2 ends at L2 height 2"
        );
        assert!(
            proven.height <= committed.height,
            "proven height {} must not exceed committed height {}",
            proven.height,
            committed.height
        );
    }
}
