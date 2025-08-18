//! Data Availability (DA) block handling for the fullnode
//!
//! This module is responsible for processing L1 blocks, extracting and verifying
//! sequencer commitments and ZK proofs, and tracking L2 finality.

use core::panic;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::{extract_zk_proofs_and_sequencer_commitments, sync_l1, ProofOrCommitment};
use citrea_common::utils::get_tangerine_activation_height_non_zero;
use citrea_primitives::forks::fork_from_block_number;
use citrea_primitives::network_to_dev_mode;
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
    /// * `start_l1_height` - Height to start syncing from
    /// * `shutdown_signal` - Signal to gracefully shut down
    #[instrument(name = "L1BlockHandler", skip_all)]
    pub async fn run(mut self, start_l1_height: u64, mut shutdown_signal: GracefulShutdown) {
        let notifier = Arc::new(Notify::new());

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
                    if let Err(e) = self.process_queued_l1_blocks().await {
                        error!("{e}");
                        return;
                    }
                },
            }
        }
    }

    /// Processes L1 blocks waiting in the queue
    async fn process_queued_l1_blocks(&mut self) -> Result<(), anyhow::Error> {
        loop {
            let Some(l1_block) = self.queued_l1_blocks.lock().await.front().cloned() else {
                break;
            };
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
                    self.ledger_db.store_pending_commitment(
                        sequencer_commitment.clone(),
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
            // Store as pending if we haven't synced all needed L2 blocks yet
            if self
                .ledger_db
                .get_pending_commitment_by_index(sequencer_commitment.index)?
                .is_none()
            {
                self.ledger_db.store_pending_commitment(
                    sequencer_commitment.clone(),
                    found_in_l1_block_height,
                )?;
                return Ok(ProcessingResult::Pending);
            } else {
                // Keep as pending if already stored as pending
                return Ok(ProcessingResult::Pending);
            }
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
    /// 1. Extracts and validates the proof using the appropriate ZKVM
    /// 2. Verifies the proof against the correct fork's code commitment
    /// 3. Processes the proof using Tangerine-specific validation logic
    ///
    /// The proofs provide cryptographic assurance that the L2 blocks were executed correctly
    /// according to the rollup's rules. This is a critical part of the rollup's security model,
    /// ensuring that invalid state transitions cannot be committed.
    ///
    /// # Arguments
    /// * `current_l1_block_height` - Current L1 block being processed
    /// * `found_in_l1_block_height` - L1 block where proof was found
    /// * `proof` - The ZK proof to process
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
    ) -> Result<ProcessingResult, ProcessingError> {
        tracing::info!(
            "Processing zk proof at height: {}",
            found_in_l1_block_height
        );
        tracing::trace!("ZK proof: {:?}", proof);

        // Extract and verify the proof using the appropriate ZKVM
        let batch_proof_output = Vm::extract_output::<BatchProofCircuitOutput>(&proof)
            .map_err(|e| anyhow!("Failed to extract batch proof output from proof: {:?}", e))?;

        // Get the code commitment for the appropriate fork
        let spec_id = fork_from_block_number(batch_proof_output.last_l2_height()).spec_id;
        let code_commitment = self
            .code_commitments_by_spec
            .get(&spec_id)
            .expect("Proof public input must contain valid spec id");

        // Verify the proof against the code commitment
        Vm::verify(
            proof.as_slice(),
            code_commitment,
            network_to_dev_mode(self.network),
        )
        .map_err(|err| anyhow!("Failed to verify proof: {:?}. Skipping it...", err))?;

        // Process the verified proof using Tangerine-specific logic
        self.process_tangerine_zk_proof(
            current_l1_block_height,
            found_in_l1_block_height,
            batch_proof_output.initial_state_root(),
            proof,
            batch_proof_output,
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

        let commitments_hashes = batch_proof_output.sequencer_commitment_hashes();
        for (index, expected_hash) in (sequencer_commitment_index_range.0
            ..=sequencer_commitment_index_range.1)
            .zip(commitments_hashes)
        {
            self.verify_sequencer_commitment_hash_by_index(
                index,
                expected_hash,
                &mut proof_is_pending,
            )?;
        }

        if proof_is_pending {
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
            return Ok(ProcessingResult::Pending);
        }

        // Check that first commitment's state root matches initial_state_root
        let start_state_root = self
                .ledger_db
                .get_l2_state_root(previous_l2_end_block_number)?
                .ok_or_else(|| {
                    anyhow!(
                        "Proof verification: Could not find state root for L2 height: {}. Skipping proof.",
                        previous_l2_end_block_number
                    )
                })?;

        if start_state_root.as_ref() != initial_state_root.as_ref() {
            return Err(SkippableError::Proof(ProofError::PreStateRootMismatch(
                hex::encode(initial_state_root),
                hex::encode(start_state_root),
            ))
            .into());
        }

        if sequencer_commitment_index_range.0 > proven_height.commitment_index + 1 {
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
        if pending_commitments.is_empty() {
            return Ok(());
        }

        // Try to process each pending commitment in order
        for (index, commitment, found_in_l1_height) in pending_commitments {
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
        if pending_proofs.is_empty() {
            return Ok(());
        }

        for ((min_index, max_index), proof, found_in_l1_height) in pending_proofs {
            match self
                .process_zk_proof(current_l1_block_height, found_in_l1_height, proof)
                .await
            {
                Err(e) => {
                    warn!(
                        "Failed to process pending proof with index {min_index}-{max_index}: {e:?}"
                    );
                    break;
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
                    debug!("Keeping proof over commitment index range {min_index}-{max_index} as pending")
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
