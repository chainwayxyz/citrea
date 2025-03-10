use core::panic;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::anyhow;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::{extract_sequencer_commitments, extract_zk_proofs, sync_l1};
use citrea_common::error::SyncError;
use citrea_common::utils::check_l2_block_exists;
use citrea_primitives::forks::fork_from_block_number;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::NodeLedgerOps;
use sov_db::schema::types::batch_proof::StoredBatchProofOutput;
use sov_db::schema::types::soft_confirmation::StoredSoftConfirmation;
use sov_db::schema::types::{SlotNumber, SoftConfirmationNumber};
use sov_modules_api::{DaSpec, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, SequencerCommitment};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
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
            match extract_zk_proofs(self.da_service.clone(), l1_block, &self.prover_da_pub_key)
                .await
            {
                Ok(proofs) => proofs,
                Err(e) => {
                    error!("Could not process L1 block: {}...skipping", e);
                    return;
                }
            };

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
                }
            }
        }

        // We do not care about the result of writing this height to the ledger db
        // So log and continue
        // Worst case scenario is that we will reprocess the same block after a restart
        let _ = self
            .ledger_db
            .set_last_scanned_l1_height(SlotNumber(l1_block.header().height()))
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
        let start_l2_height = sequencer_commitment.l2_start_block_number;
        let end_l2_height = sequencer_commitment.l2_end_block_number;

        tracing::info!(
            "Processing sequencer commitment for L2 Range = {}-{} at L1 height {}.",
            start_l2_height,
            end_l2_height,
            l1_block.header().height(),
        );

        // Traverse each item's field of vector of transactions, put them in merkle tree
        // and compare the root with the one from the ledger
        let stored_soft_confirmations: Vec<StoredSoftConfirmation> =
            self.ledger_db.get_soft_confirmation_range(
                &(SoftConfirmationNumber(start_l2_height)..=SoftConfirmationNumber(end_l2_height)),
            )?;

        // Make sure that the number of stored soft confirmations is equal to the range's length.
        // Otherwise, if it is smaller, then we don't have some L2 blocks within the range
        // synced yet.
        if stored_soft_confirmations.len() < ((end_l2_height - start_l2_height) as usize) {
            return Err(SyncError::MissingL2(
                "L2 range not synced yet",
                start_l2_height,
                end_l2_height,
            ));
        }

        let soft_confirmations_tree = MerkleTree::<Sha256>::from_leaves(
            stored_soft_confirmations
                .iter()
                .map(|x| x.hash)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        if soft_confirmations_tree.root() != Some(sequencer_commitment.merkle_root) {
            return Err(anyhow!(
                "Merkle root mismatch - expected 0x{} but got 0x{}. Skipping commitment.",
                hex::encode(
                    soft_confirmations_tree
                        .root()
                        .ok_or(anyhow!("Could not calculate soft confirmation tree root"))?
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
            self.ledger_db.put_l2_block_status(
                SoftConfirmationNumber(i),
                SoftConfirmationStatus::Finalized,
            )?;
        }

        self.ledger_db.set_l2_range_by_commitment_merkle_root(
            sequencer_commitment.merkle_root,
            (
                SoftConfirmationNumber(start_l2_height),
                SoftConfirmationNumber(end_l2_height),
            ),
        )?;

        self.ledger_db
            .set_last_commitment_l2_height(SoftConfirmationNumber(end_l2_height))?;

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
            batch_proof_output
                .sequencer_commitment_merkle_roots()
                .clone(),
            proof,
            batch_proof_output.into(),
        )
    }

    fn process_fork2_zk_proof(
        &self,
        l1_block: &Da::FilteredBlock,
        initial_state_root: [u8; 32],
        soft_confirmation_merkle_roots: Vec<[u8; 32]>,
        raw_proof: Proof,
        batch_proof_output: StoredBatchProofOutput,
    ) -> Result<(), SyncError> {
        // make sure init roots match <- TODO: with proposed changes in issues this will be unnecessary
        for root in soft_confirmation_merkle_roots {
            // make sure sequencer commitment soft confirmation merkle root match
            // since we wouldn't have the sequencer commitment in the ledger db
            // this makes sure the sequencer commitment exists
            let seq_comm_range = self
                .ledger_db
                .get_l2_range_by_commitment_merkle_root(root)?
                .ok_or(SyncError::SequencerCommitmentNotFound(root))?;

            let l2_height_before_comm_range = seq_comm_range.0 .0 - 1;
            let state_root_prior_soft_confirmation = self
                .ledger_db
                .get_l2_state_root(l2_height_before_comm_range)?
                .ok_or_else(|| {
                    anyhow!(
                        "Proof verification: Could not find state root for L2 height: {}. Skipping proof.",
                        l2_height_before_comm_range
                    )
                })?;

            if state_root_prior_soft_confirmation.as_ref() != initial_state_root.as_ref() {
                return Err(anyhow!(
                    "Proof verification: For a known and verified sequencer commitment. Pre state root mismatch - expected 0x{} but got 0x{}. Skipping proof.",
                    hex::encode(state_root_prior_soft_confirmation),
                    hex::encode(initial_state_root)
                ).into());
            }

            for i in seq_comm_range.0 .0..=seq_comm_range.1 .0 {
                self.ledger_db.put_l2_block_status(
                    SoftConfirmationNumber(i),
                    SoftConfirmationStatus::Proven,
                )?;
            }
        }

        // store in ledger db
        self.ledger_db.update_verified_proof_data(
            l1_block.header().height(),
            raw_proof,
            batch_proof_output,
        )?;

        Ok(())
    }
}
