use core::panic;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::anyhow;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::{extract_sequencer_commitments, extract_zk_proofs, sync_l1};
use citrea_common::error::SyncError;
use citrea_common::utils::check_l2_block_exists;
use citrea_primitives::forks::{fork_from_block_number, get_fork2_activation_height_non_zero};
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::NodeLedgerOps;
use sov_db::schema::types::l2_block::StoredL2Block;
use sov_db::schema::types::{L2BlockNumber, SlotNumber};
use sov_modules_api::{DaSpec, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, SequencerCommitment};
use sov_rollup_interface::rpc::L2BlockStatus;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::metrics::FULLNODE_METRICS;

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

    pub async fn run(mut self, start_l1_height: u64, cancellation_token: CancellationToken) {
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
                _ = cancellation_token.cancelled() => {
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

        let sequencer_commitments = extract_sequencer_commitments(
            self.da_service.clone(),
            l1_block,
            &self.sequencer_da_pub_key,
        );

        let zk_proofs =
            extract_zk_proofs(self.da_service.clone(), l1_block, &self.prover_da_pub_key).await;

        if !sequencer_commitments.is_empty() {
            // If the L2 range does not exist, we break off the current process call
            // We retry the L1 block at a later tick.
            if !check_l2_block_exists(
                &self.ledger_db,
                sequencer_commitments[sequencer_commitments.len() - 1].l2_end_block_number,
            ) {
                warn!("L1 commitment received, but L2 range is not synced yet...");
                return;
            }
        }

        for zk_proof in zk_proofs.clone().iter() {
            if let Err(e) = self.process_zk_proof(l1_block, zk_proof.clone()).await {
                match e {
                    SyncError::MissingL2(msg, start_l2_height, end_l2_height) => {
                        warn!("Could not completely process ZK proofs. Missing L2 blocks {:?} - {:?}. msg = {}", start_l2_height, end_l2_height, msg);
                        return;
                    }
                    SyncError::Error(e) => {
                        error!("Could not process ZK proofs: {}... skipping...", e);
                    }
                    SyncError::SequencerCommitmentNotFound(merkle_root) => {
                        error!("Could not process ZK proofs: Sequencer commitment not found for merkle root: 0x{}... skipping...", hex::encode(merkle_root));
                    }
                    SyncError::SequencerCommitmentWithIndexNotFound(idx) => {
                        error!("Could not process ZK proofs: Sequencer commitment with index {} not found... skipping...", idx);
                    }
                }
            }
        }

        for sequencer_commitment in sequencer_commitments.clone().iter() {
            if let Err(e) = self
                .process_sequencer_commitment(l1_block, sequencer_commitment)
                .await
            {
                match e {
                    SyncError::MissingL2(msg, start_l2_height, end_l2_height) => {
                        warn!("Could not completely process sequencer commitments. Missing L2 blocks {:?} - {:?}, msg = {}", start_l2_height, end_l2_height, msg);
                        return;
                    }
                    SyncError::Error(e) => {
                        error!("Could not process sequencer commitments: {}... skipping", e);
                    }
                    SyncError::SequencerCommitmentNotFound(_) => unreachable!("Error irrelevant!"),
                    SyncError::SequencerCommitmentWithIndexNotFound(_) => {
                        unreachable!("Error irrelevant!")
                    }
                }
            }
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
    ) -> Result<(), SyncError> {
        let start_l2_height = if sequencer_commitment.index == 1 {
            get_fork2_activation_height_non_zero()
        } else {
            self.ledger_db
                .get_commitment_by_index(sequencer_commitment.index - 1)?
                .expect("Commitment must exist")
                .l2_end_block_number
                + 1
        };
        let end_l2_height = sequencer_commitment.l2_end_block_number;

        tracing::info!(
            "Processing sequencer commitment for L2 Range = {}-{} at L1 height {}.",
            start_l2_height,
            end_l2_height,
            l1_block.header().height(),
        );

        // Traverse each item's field of vector of transactions, put them in merkle tree
        // and compare the root with the one from the ledger
        let stored_l2_blocks: Vec<StoredL2Block> = self
            .ledger_db
            .get_l2_block_range(&(L2BlockNumber(start_l2_height)..=L2BlockNumber(end_l2_height)))?;

        // Make sure that the number of stored l2 blocks is equal to the range's length.
        // Otherwise, if it is smaller, then we don't have some L2 blocks within the range
        // synced yet.
        if stored_l2_blocks.len() < ((end_l2_height - start_l2_height) as usize) {
            return Err(SyncError::MissingL2(
                "L2 range not synced yet",
                start_l2_height,
                end_l2_height,
            ));
        }

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

        for i in start_l2_height..=end_l2_height {
            self.ledger_db
                .put_l2_block_status(L2BlockNumber(i), L2BlockStatus::Finalized)?;
        }

        self.ledger_db.set_l2_range_by_commitment_merkle_root(
            sequencer_commitment.merkle_root,
            (L2BlockNumber(start_l2_height), L2BlockNumber(end_l2_height)),
        )?;

        self.ledger_db
            .put_commitment_by_index(sequencer_commitment)?;

        Ok(())
    }

    async fn process_zk_proof(
        &self,
        l1_block: &Da::FilteredBlock,
        proof: Proof,
    ) -> Result<(), SyncError> {
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

        self.process_fork2_zk_proof(
            l1_block,
            batch_proof_output.initial_state_root(),
            proof,
            batch_proof_output,
        )
    }

    fn process_fork2_zk_proof(
        &self,
        l1_block: &Da::FilteredBlock,
        initial_state_root: [u8; 32],
        raw_proof: Proof,
        batch_proof_output: BatchProofCircuitOutput,
    ) -> Result<(), SyncError> {
        let sequencer_commitment_index_range =
            batch_proof_output.sequencer_commitment_index_range();
        // make sure init roots match <- TODO: with proposed changes in issues this will be unnecessary
        let previous_l2_end_block_number = match batch_proof_output.previous_commitment_index() {
            Some(idx) => {
                let previous_sequencer_commitment = self
                    .ledger_db
                    // TODO: This works for now, but once we generate proofs by taking commitments from mempool
                    // we will need to store the commitments earlier to process proofs, maybe just process commitments first for that
                    .get_commitment_by_index(idx)?
                    .ok_or(SyncError::SequencerCommitmentWithIndexNotFound(idx))?;

                // Check previous sequencer commitment hash
                if previous_sequencer_commitment.serialize_and_calculate_sha_256()
                    != batch_proof_output
                        .previous_commitment_hash()
                        .expect("If index exists so must hash")
                {
                    return Err(anyhow!(
                        "Proof verification: For a known and verified sequencer commitment. Hash mismatch - expected 0x{} but got 0x{}. Skipping proof.",
                        hex::encode(previous_sequencer_commitment.serialize_and_calculate_sha_256()),
                        hex::encode(batch_proof_output.previous_commitment_hash().expect("If index exists so must hash"))
                    ).into());
                }
                previous_sequencer_commitment.l2_end_block_number
            }
            // If there is no previous seq comm hash then this must be the first post fork2 commitment
            None => get_fork2_activation_height_non_zero() - 1,
        };

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

        let mut l2_start_height = previous_l2_end_block_number + 1;
        for (index, expected_hash) in (sequencer_commitment_index_range.0
            ..=sequencer_commitment_index_range.1)
            .zip(batch_proof_output.sequencer_commitment_hashes())
        {
            // Check if hash matches
            let sequencer_commitment = self
                .ledger_db
                .get_commitment_by_index(index)?
                .ok_or(SyncError::SequencerCommitmentWithIndexNotFound(index))?;

            if sequencer_commitment.serialize_and_calculate_sha_256() != expected_hash {
                return Err(anyhow!(
                    "Proof verification: For a known and verified sequencer commitment. Hash mismatch - expected 0x{} but got 0x{}. Skipping proof.",
                    hex::encode(sequencer_commitment.serialize_and_calculate_sha_256()),
                    hex::encode(expected_hash)
                ).into());
            }

            for i in l2_start_height..=sequencer_commitment.l2_end_block_number {
                self.ledger_db
                    .put_l2_block_status(L2BlockNumber(i), L2BlockStatus::Proven)?;
            }
            l2_start_height = sequencer_commitment.l2_end_block_number + 1;
        }

        // store in ledger db
        self.ledger_db.update_verified_proof_data(
            l1_block.header().height(),
            raw_proof,
            batch_proof_output.into(),
        )?;

        Ok(())
    }
}
