use core::panic;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::anyhow;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::{extract_zk_proofs_and_sequencer_commitments, sync_l1, ProofOrCommitment};
use citrea_common::error::SyncError;
use citrea_primitives::forks::{fork_from_block_number, get_tangerine_activation_height_non_zero};
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
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use crate::metrics::FULLNODE_METRICS;

enum ProcessingResult {
    Success,
    Discarded,
    Pending,
}

pub struct L1BlockHandler<Vm, Da, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: NodeLedgerOps,
{
    ledger_db: DB,
    da_service: Arc<Da>,
    sequencer_da_pub_key: Vec<u8>,
    prover_da_pub_key: Vec<u8>,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    pending_l1_blocks: Arc<Mutex<VecDeque<<Da as DaService>::FilteredBlock>>>,
    backup_manager: Arc<BackupManager>,
}

impl<Vm, Da, DB> L1BlockHandler<Vm, Da, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: NodeLedgerOps + Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
            pending_l1_blocks: Arc::new(Mutex::new(VecDeque::new())),
            backup_manager,
        }
    }

    pub async fn run(mut self, start_l1_height: u64, mut shutdown_signal: GracefulShutdown) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;

        let l1_sync_worker = sync_l1(
            start_l1_height,
            self.da_service.clone(),
            self.pending_l1_blocks.clone(),
            self.l1_block_cache.clone(),
            FULLNODE_METRICS.scan_l1_block.clone(),
        );
        tokio::pin!(l1_sync_worker);

        loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    return;
                }
                _ = &mut l1_sync_worker => {},
                _ = interval.tick() => {
                    self.process_l1_block().await
                },
            }
        }
    }

    async fn process_l1_block(&mut self) {
        let _l1_lock = self.backup_manager.start_l1_processing().await;
        let mut pending_l1_blocks = self.pending_l1_blocks.lock().await;

        let Some(l1_block) = pending_l1_blocks.front() else {
            return;
        };

        let short_header_proof: <<Da as DaService>::Spec as DaSpec>::ShortHeaderProof =
            Da::block_to_short_header_proof(l1_block.clone());
        self.ledger_db
            .put_short_header_proof_by_l1_hash(
                &l1_block.header().hash().into(),
                borsh::to_vec(&short_header_proof).expect("Should serialize short header proof"),
            )
            .expect("Should save short header proof to ledger db");

        let l1_height = l1_block.header().height();
        info!("Processing L1 block at height: {}", l1_height);

        // Set the l1 height of the l1 hash
        self.ledger_db
            .set_l1_height_of_l1_hash(l1_block.header().hash().into(), l1_height)
            .unwrap();

        let commitments_and_proofs = extract_zk_proofs_and_sequencer_commitments(
            self.da_service.clone(),
            l1_block,
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
                            l1_block.header().height()
                        );
                        continue;
                    }
                    if let Err(e) = self
                        .process_sequencer_commitment(l1_block, &commitment)
                        .await
                    {
                        match e {
                            SyncError::Error(e) => {
                                error!(
                                    "Could not process sequencer commitments: {}... skipping",
                                    e
                                );
                            }
                            SyncError::SequencerCommitmentNotFound(_) => {
                                unreachable!("Error irrelevant!")
                            }
                            SyncError::SequencerCommitmentWithIndexNotFound(_) => {
                                unreachable!("Error irrelevant!")
                            }
                            SyncError::UnknownL1Hash => unreachable!("Error irrelevant!"),
                            SyncError::SequencerCommitmentMissingForProof(_) => {
                                unreachable!("Error irrelevant!")
                            }
                        }
                    }
                }
                ProofOrCommitment::Proof(proof) => {
                    if let Err(e) = self.process_zk_proof(l1_block, proof).await {
                        match e {
                            SyncError::Error(e) => {
                                error!("Could not process ZK proofs: {}... skipping...", e);
                            }
                            SyncError::SequencerCommitmentNotFound(merkle_root) => {
                                error!("Could not process ZK proofs: Sequencer commitment not found for merkle root: 0x{}... skipping...", hex::encode(merkle_root));
                            }
                            SyncError::SequencerCommitmentWithIndexNotFound(idx) => {
                                error!("Could not process ZK proofs: Sequencer commitment with index {} not found... skipping...", idx);
                            }
                            SyncError::UnknownL1Hash => {
                                error!("Could not process ZK proofs: Batch proof output last_l1_hash_on_bitcoin_light_client_contract isn't known")
                            }
                            SyncError::SequencerCommitmentMissingForProof(index) => {
                                error!("Could not process ZK proofs: Commitment index {index} is missing for proof")
                            }
                        }
                    }
                }
            }
        }

        if let Err(e) = self.process_pending_commitments(l1_block).await {
            error!("Error processing pending commitments: {e:?}");
        }

        if let Err(e) = self.process_pending_proofs(l1_block).await {
            error!("Error processing pending proofs: {e:?}");
        }

        // We do not care about the result of writing this height to the ledger db
        // So log and continue
        // Worst case scenario is that we will reprocess the same block after a restart
        let _ = self
            .ledger_db
            .set_last_scanned_l1_height(SlotNumber(l1_height))
            .map_err(|e| {
                error!("Could not set last scanned l1 height: {}", e);
            });

        FULLNODE_METRICS.current_l1_block.set(l1_height as f64);

        pending_l1_blocks.pop_front();
    }

    async fn process_sequencer_commitment(
        &self,
        l1_block: &Da::FilteredBlock,
        sequencer_commitment: &SequencerCommitment,
    ) -> Result<ProcessingResult, SyncError> {
        // Skip if we already processed commitment with same index
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
        if let Some(committed_height) = self
            .ledger_db
            .get_highest_l2_height_for_status(L2HeightStatus::Committed, None)?
        {
            // Only proceed if the commitment height and index are higher than the stored one
            if end_l2_height <= committed_height.height {
                info!(
                    "Skipping sequencer commitment with height {end_l2_height} as it is not strictly superior to existing commitment with height {}",
                    committed_height.height,
                );
                return Ok(ProcessingResult::Discarded);
            }

            if sequencer_commitment.index <= committed_height.commitment_index {
                info!(
                    "Skipping sequencer commitment with index {} as it is not strictly superior to the existing commited one",
                    sequencer_commitment.index,
                );
                return Ok(ProcessingResult::Discarded);
            }
        }

        let start_l2_height = if sequencer_commitment.index == 1 {
            get_tangerine_activation_height_non_zero()
        } else {
            match self
                .ledger_db
                .get_commitment_by_index(sequencer_commitment.index - 1)?
            {
                Some(previous_commitment) => previous_commitment.l2_end_block_number + 1,
                None => {
                    // Store the out of order commitment as pending
                    info!(
                            "Commitment with index {} is missing its predecessor (index {}). Storing as pending.",
                            sequencer_commitment.index,
                            sequencer_commitment.index - 1
                        );
                    self.ledger_db
                        .store_pending_commitment(sequencer_commitment.clone())?;
                    return Ok(ProcessingResult::Pending);
                }
            }
        };

        info!(
            "Processing sequencer commitment for L2 Range = {}-{} at L1 height {}.",
            start_l2_height,
            end_l2_height,
            l1_block.header().height(),
        );

        // Check first if the end l2 height is within the range of the last scanned l2 height
        let head_l2_height = self
            .ledger_db
            .get_head_l2_block_height()?
            .unwrap_or_default();
        if end_l2_height > head_l2_height {
            if self
                .ledger_db
                .get_pending_commitment_by_index(sequencer_commitment.index)?
                .is_none()
            {
                info!(
                    "Commitment with index: {} L2 blocks not synced yet. Range: {}-{}, merkle root: {} Storing commitment as pending.",
                    sequencer_commitment.index,
                    start_l2_height,
                    end_l2_height,
                    hex::encode(sequencer_commitment.merkle_root)
                );
                self.ledger_db
                    .store_pending_commitment(sequencer_commitment.clone())?;
                return Ok(ProcessingResult::Pending);
            } else {
                // This branch will be reached when we are processing pending commitments, and the commitment is still pending
                return Ok(ProcessingResult::Pending);
            }
        }

        // Traverse each item's field of vector of transactions, put them in merkle tree
        // and compare the root with the one from the ledger
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

        if l2_blocks_tree.root() != Some(sequencer_commitment.merkle_root) {
            return Err(anyhow!(
                "Merkle root mismatch - expected 0x{} but got 0x{}. Skipping commitment.",
                hex::encode(
                    l2_blocks_tree
                        .root()
                        .ok_or(anyhow!("Could not calculate l2 block tree root"))?
                ),
                hex::encode(sequencer_commitment.merkle_root)
            )
            .into());
        }

        self.ledger_db.update_commitments_on_da_slot(
            l1_block.header().height(),
            sequencer_commitment.clone(),
        )?;

        self.ledger_db.set_l2_range_by_commitment_merkle_root(
            sequencer_commitment.merkle_root,
            (L2BlockNumber(start_l2_height), L2BlockNumber(end_l2_height)),
        )?;

        self.ledger_db
            .put_commitment_by_index(sequencer_commitment)?;

        self.ledger_db.set_l2_height_status(
            L2HeightStatus::Committed,
            l1_block.header().height(),
            L2HeightAndIndex {
                height: end_l2_height,
                commitment_index: sequencer_commitment.index,
            },
        )?;

        Ok(ProcessingResult::Success)
    }

    async fn process_zk_proof(
        &self,
        l1_block: &Da::FilteredBlock,
        proof: Proof,
    ) -> Result<ProcessingResult, SyncError> {
        tracing::info!(
            "Processing zk proof at height: {}",
            l1_block.header().height()
        );
        tracing::trace!("ZK proof: {:?}", proof);

        let batch_proof_output = Vm::extract_output::<BatchProofCircuitOutput>(&proof)
            .map_err(|e| anyhow!("Failed to extract batch proof output from proof: {:?}", e))?;
        let spec_id = fork_from_block_number(batch_proof_output.last_l2_height()).spec_id;
        let code_commitment = self
            .code_commitments_by_spec
            .get(&spec_id)
            .expect("Proof public input must contain valid spec id");
        Vm::verify(proof.as_slice(), code_commitment)
            .map_err(|err| anyhow!("Failed to verify proof: {:?}. Skipping it...", err))?;

        self.process_tangerine_zk_proof(
            l1_block,
            batch_proof_output.initial_state_root(),
            proof,
            batch_proof_output,
        )
    }

    fn process_tangerine_zk_proof(
        &self,
        l1_block: &Da::FilteredBlock,
        initial_state_root: [u8; 32],
        raw_proof: Proof,
        batch_proof_output: BatchProofCircuitOutput,
    ) -> Result<ProcessingResult, SyncError> {
        let last_l1_hash_on_bitcoin_light_client_contract =
            batch_proof_output.last_l1_hash_on_bitcoin_light_client_contract();
        if self
            .ledger_db
            .get_l1_height_of_l1_hash(last_l1_hash_on_bitcoin_light_client_contract)?
            .is_none()
        {
            return Err(SyncError::UnknownL1Hash);
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
            return Err(anyhow!(
                    "Proof verification: For a known and verified sequencer commitment. Pre state root mismatch - expected 0x{} but got 0x{}. Skipping proof.",
                    hex::encode(initial_state_root),
                    hex::encode(start_state_root)
                ).into());
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
            )?;
            return Ok(ProcessingResult::Pending);
        }

        // store in ledger db
        self.ledger_db.update_verified_proof_data(
            l1_block.header().height(),
            raw_proof,
            batch_proof_output.into(),
        )?;

        self.ledger_db.set_l2_height_status(
            L2HeightStatus::Proven,
            l1_block.header().height(),
            L2HeightAndIndex {
                height: end_l2_height,
                commitment_index: sequencer_commitment_index_range.1,
            },
        )?;

        Ok(ProcessingResult::Success)
    }

    async fn process_pending_commitments(
        &self,
        l1_block: &Da::FilteredBlock,
    ) -> Result<(), SyncError> {
        let pending_commitments = self.ledger_db.get_pending_commitments()?;
        if pending_commitments.is_empty() {
            return Ok(());
        }

        for (index, commitment) in pending_commitments {
            // Check if we can process this commitment now
            if self.ledger_db.get_commitment_by_index(index - 1)?.is_some() {
                match self
                    .process_sequencer_commitment(l1_block, &commitment)
                    .await
                {
                    Err(e) => {
                        warn!("Failed to process pending commitment with index {index}: {e:?}");
                        break;
                    }
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
                // Breaking since pending commitments are sorted and we won't be to process anymore from then on
                break;
            }
        }

        Ok(())
    }

    async fn process_pending_proofs(&self, l1_block: &Da::FilteredBlock) -> Result<(), SyncError> {
        let pending_proofs = self.ledger_db.get_pending_proofs()?;
        if pending_proofs.is_empty() {
            return Ok(());
        }

        for ((min_index, max_index), proof) in pending_proofs {
            match self.process_zk_proof(l1_block, proof).await {
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

    /// Returns l2 end block number of the commitment if verified
    fn verify_sequencer_commitment_hash_by_index(
        &self,
        idx: u32,
        expected_hash: [u8; 32],
        proof_is_pending: &mut bool,
    ) -> Result<u64, SyncError> {
        let sequencer_commitment =
            if let Some(sequencer_commitment) = self.ledger_db.get_commitment_by_index(idx)? {
                sequencer_commitment
            } else if let Some(sequencer_commitment) =
                self.ledger_db.get_pending_commitment_by_index(idx)?
            {
                // If we have a pending commitment, we need to store the proof as pending
                info!("Proof has a pending commitment with index: {}.", idx);
                *proof_is_pending = true;
                sequencer_commitment
            } else {
                return Err(SyncError::SequencerCommitmentMissingForProof(idx));
            };

        // Check if hash matches
        if sequencer_commitment.serialize_and_calculate_sha_256() != expected_hash {
            return Err(anyhow!(
                "Proof verification: For a known and verified sequencer commitment. Hash mismatch - expected 0x{} but got 0x{}. Skipping proof.",
                hex::encode(sequencer_commitment.serialize_and_calculate_sha_256()),
                hex::encode(expected_hash)
            )
            .into());
        }
        Ok(sequencer_commitment.l2_end_block_number)
    }
}
