use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::anyhow;
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
use sov_modules_api::Zkvm;
use sov_rollup_interface::da::{BlockHeaderTrait, SequencerCommitment};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::batch_proof::output::v1::BatchProofCircuitOutputV1;
use sov_rollup_interface::zk::batch_proof::output::v2::BatchProofCircuitOutputV2;
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
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
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    prover_da_pub_key: Vec<u8>,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    pending_l1_blocks: Arc<Mutex<VecDeque<<Da as DaService>::FilteredBlock>>>,
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
        sequencer_pub_key: Vec<u8>,
        sequencer_da_pub_key: Vec<u8>,
        prover_da_pub_key: Vec<u8>,
        code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
        l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    ) -> Self {
        Self {
            ledger_db,
            da_service,
            sequencer_pub_key,
            sequencer_da_pub_key,
            prover_da_pub_key,
            code_commitments_by_spec,
            l1_block_cache,
            pending_l1_blocks: Arc::new(Mutex::new(VecDeque::new())),
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
        let mut pending_l1_blocks = self.pending_l1_blocks.lock().await;

        let Some(l1_block) = pending_l1_blocks.front() else {
            return;
        };

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
                        error!("Could not process ZK proofs: {}...skipping", e);
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
            self.ledger_db.put_soft_confirmation_status(
                SoftConfirmationNumber(i),
                SoftConfirmationStatus::Finalized,
            )?;
        }
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

        let (
            last_active_spec_id,
            batch_proof_output,
            da_slot_hash,
            preproven_commitments,
            sequencer_commitments_range,
            initial_state_root,
        ) = match Vm::extract_output::<BatchProofCircuitOutputV3>(&proof) {
            Ok(output) => (
                fork_from_block_number(output.last_l2_height).spec_id,
                StoredBatchProofOutput::from(output.clone()),
                output.da_slot_hash,
                output.preproven_commitments,
                output.sequencer_commitments_range,
                output.initial_state_root,
            ),
            Err(e) => {
                info!("Failed to extract post fork 2 output from proof: {:?}. Trying to extract pre fork 2 output", e);
                match Vm::extract_output::<BatchProofCircuitOutputV2>(&proof) {
                    Ok(output) => {
                        if output.sequencer_da_public_key != self.sequencer_da_pub_key
                            || output.sequencer_public_key != self.sequencer_pub_key
                        {
                            return Err(anyhow!(
                "Proof verification: Sequencer public key or sequencer da public key mismatch. Skipping proof."
            ).into());
                        }
                        (
                            fork_from_block_number(output.last_l2_height).spec_id,
                            StoredBatchProofOutput::from(output.clone()),
                            output.da_slot_hash,
                            output.preproven_commitments,
                            output.sequencer_commitments_range,
                            output.initial_state_root,
                        )
                    }
                    Err(e) => {
                        info!("Failed to extract kumquat fork output from proof: {:?}. Trying to extract genesis fork output", e);
                        let output = Vm::extract_output::<BatchProofCircuitOutputV1>(&proof)
                            .expect("Should be able to extract either pre or post fork 1 output");
                        if output.sequencer_da_public_key != self.sequencer_da_pub_key
                            || output.sequencer_public_key != self.sequencer_pub_key
                        {
                            return Err(anyhow!(
                "Proof verification: Sequencer public key or sequencer da public key mismatch. Skipping proof."
            ).into());
                        }
                        // If we got output of pre fork 1 that means we are in genesis
                        (
                            SpecId::Genesis,
                            StoredBatchProofOutput::from(output.clone()),
                            output.da_slot_hash,
                            output.preproven_commitments,
                            output.sequencer_commitments_range,
                            output.initial_state_root,
                        )
                    }
                }
            }
        };

        // TODO: Do this check for v1 only

        let code_commitment = self
            .code_commitments_by_spec
            .get(&last_active_spec_id)
            .expect("Proof public input must contain valid spec id");
        Vm::verify(proof.as_slice(), code_commitment)
            .map_err(|err| anyhow!("Failed to verify proof: {:?}. Skipping it...", err))?;

        let l1_hash = da_slot_hash;

        // This is the l1 height where the sequencer commitment was read by the prover and proof generated by those commitments
        // We need to get commitments in this l1 height and set them as proven
        let l1_height = match self.ledger_db.get_l1_height_of_l1_hash(l1_hash)? {
            Some(l1_height) => l1_height,
            None => {
                return Err(anyhow!(
                    "Proof verification: L1 height not found for l1 hash: {:?}. Skipping proof.",
                    l1_hash
                )
                .into());
            }
        };

        let mut commitments_on_da_slot =
            match self.ledger_db.get_commitments_on_da_slot(l1_height)? {
                Some(commitments) => commitments,
                None => {
                    return Err(anyhow!(
                    "Proof verification: No commitments found for l1 height: {}. Skipping proof.",
                    l1_height
                )
                    .into());
                }
            };

        commitments_on_da_slot.sort();

        let excluded_commitment_indices = preproven_commitments.clone();
        let filtered_commitments: Vec<SequencerCommitment> = commitments_on_da_slot
            .into_iter()
            .enumerate()
            .filter(|(index, _)| !excluded_commitment_indices.contains(index))
            .map(|(_, commitment)| commitment)
            .collect();

        let l2_height =
            filtered_commitments[sequencer_commitments_range.0 as usize].l2_start_block_number;
        // Fetch the block prior to the one at l2_height so compare state roots

        let prior_soft_confirmation_post_state_root = self
            .ledger_db
            .get_l2_state_root(l2_height - 1)?
            .ok_or_else(|| {
                anyhow!(
                "Proof verification: Could not find state root for L2 height: {}. Skipping proof.",
                l2_height - 1
            )
            })?;

        if prior_soft_confirmation_post_state_root.as_ref() != initial_state_root.as_ref() {
            return Err(anyhow!(
                    "Proof verification: For a known and verified sequencer commitment. Pre state root mismatch - expected 0x{} but got 0x{}. Skipping proof.",
                    hex::encode(prior_soft_confirmation_post_state_root),
                    hex::encode(initial_state_root)
                ).into());
        }

        for commitment in filtered_commitments
            .iter()
            .skip(sequencer_commitments_range.0 as usize)
            .take((sequencer_commitments_range.1 - sequencer_commitments_range.0 + 1) as usize)
        {
            let l2_start_height = commitment.l2_start_block_number;
            let l2_end_height = commitment.l2_end_block_number;
            for i in l2_start_height..=l2_end_height {
                self.ledger_db.put_soft_confirmation_status(
                    SoftConfirmationNumber(i),
                    SoftConfirmationStatus::Proven,
                )?;
            }
        }
        // store in ledger db
        self.ledger_db.update_verified_proof_data(
            l1_block.header().height(),
            proof.clone(),
            batch_proof_output,
        )?;
        Ok(())
    }
}
