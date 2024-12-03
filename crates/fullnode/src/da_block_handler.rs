use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::anyhow;
use borsh::{BorshDeserialize, BorshSerialize};
use citrea_common::cache::L1BlockCache;
use citrea_common::da::{extract_sequencer_commitments, extract_zk_proofs, get_da_block_at_height};
use citrea_common::error::SyncError;
use citrea_common::utils::check_l2_range_exists;
use citrea_primitives::forks::FORKS;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_db::ledger_db::NodeLedgerOps;
use sov_db::schema::types::{
    BatchNumber, SlotNumber, StoredBatchProofOutput, StoredSoftConfirmation,
};
use sov_modules_api::{Context, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, SequencerCommitment};
use sov_rollup_interface::fork::fork_from_block_number;
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::{BatchProofCircuitOutput, Proof, ZkvmHost};
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub(crate) struct L1BlockHandler<C, Vm, Da, StateRoot, DB>
where
    C: Context,
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: NodeLedgerOps,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
{
    ledger_db: DB,
    da_service: Arc<Da>,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    prover_da_pub_key: Vec<u8>,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    pending_l1_blocks: VecDeque<<Da as DaService>::FilteredBlock>,
    _context: PhantomData<C>,
    _state_root: PhantomData<StateRoot>,
}

impl<C, Vm, Da, StateRoot, DB> L1BlockHandler<C, Vm, Da, StateRoot, DB>
where
    C: Context,
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: NodeLedgerOps + Clone,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
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
            pending_l1_blocks: VecDeque::new(),
            _context: PhantomData,
            _state_root: PhantomData,
        }
    }

    pub async fn run(mut self, start_l1_height: u64, cancellation_token: CancellationToken) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;

        let (l1_tx, mut l1_rx) = mpsc::channel(1);
        let l1_sync_worker = sync_l1(
            start_l1_height,
            self.da_service.clone(),
            l1_tx,
            self.l1_block_cache.clone(),
        );
        tokio::pin!(l1_sync_worker);

        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                }
                _ = &mut l1_sync_worker => {},
                Some(l1_block) = l1_rx.recv() => {
                    self.pending_l1_blocks.push_back(l1_block);
                },
                _ = interval.tick() => {
                    self.process_l1_block().await
                },
            }
        }
    }

    async fn process_l1_block(&mut self) {
        if self.pending_l1_blocks.is_empty() {
            return;
        }
        let l1_block = self
            .pending_l1_blocks
            .front()
            .expect("Just checked pending L1 blocks is not empty");
        let l1_height = l1_block.header().height();

        // Set the l1 height of the l1 hash
        self.ledger_db
            .set_l1_height_of_l1_hash(l1_block.header().hash().into(), l1_height)
            .unwrap();

        let sequencer_commitments = extract_sequencer_commitments(
            self.da_service.clone(),
            l1_block.clone(),
            &self.sequencer_da_pub_key,
        );
        let zk_proofs = match extract_zk_proofs(
            self.da_service.clone(),
            l1_block.clone(),
            &self.prover_da_pub_key,
        )
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
            if !check_l2_range_exists(
                &self.ledger_db,
                sequencer_commitments[0].l2_start_block_number,
                sequencer_commitments[sequencer_commitments.len() - 1].l2_end_block_number,
            ) {
                return;
            }
        }

        for zk_proof in zk_proofs.clone().iter() {
            if let Err(e) = self
                .process_zk_proof(l1_block.clone(), zk_proof.clone())
                .await
            {
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

        self.pending_l1_blocks.pop_front();
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
                &(BatchNumber(start_l2_height)..=BatchNumber(end_l2_height)),
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
            self.ledger_db
                .put_soft_confirmation_status(BatchNumber(i), SoftConfirmationStatus::Finalized)?;
        }
        self.ledger_db
            .set_last_commitment_l2_height(BatchNumber(end_l2_height))?;

        Ok(())
    }

    async fn process_zk_proof(
        &self,
        l1_block: Da::FilteredBlock,
        proof: Proof,
    ) -> Result<(), SyncError> {
        tracing::info!(
            "Processing zk proof at height: {}",
            l1_block.header().height()
        );
        tracing::trace!("ZK proof: {:?}", proof);

        // TODO: select output version based on spec
        let batch_proof_output = Vm::extract_output::<
            <Da as DaService>::Spec,
            BatchProofCircuitOutput<<Da as DaService>::Spec, StateRoot>,
        >(&proof)
        .expect("Proof should be deserializable");
        if batch_proof_output.sequencer_da_public_key != self.sequencer_da_pub_key
            || batch_proof_output.sequencer_public_key != self.sequencer_pub_key
        {
            return Err(anyhow!(
                "Proof verification: Sequencer public key or sequencer da public key mismatch. Skipping proof."
            ).into());
        }

        let last_active_spec_id =
            fork_from_block_number(FORKS, batch_proof_output.last_l2_height).spec_id;
        let code_commitment = self
            .code_commitments_by_spec
            .get(&last_active_spec_id)
            .expect("Proof public input must contain valid spec id");
        Vm::verify(proof.as_slice(), code_commitment)
            .map_err(|err| anyhow!("Failed to verify proof: {:?}. Skipping it...", err))?;

        let stored_batch_proof_output = StoredBatchProofOutput {
            initial_state_root: batch_proof_output.initial_state_root.as_ref().to_vec(),
            final_state_root: batch_proof_output.final_state_root.as_ref().to_vec(),
            state_diff: batch_proof_output.state_diff,
            da_slot_hash: batch_proof_output.da_slot_hash.clone().into(),
            sequencer_commitments_range: batch_proof_output.sequencer_commitments_range,
            sequencer_public_key: batch_proof_output.sequencer_public_key,
            sequencer_da_public_key: batch_proof_output.sequencer_da_public_key,
            preproven_commitments: batch_proof_output.preproven_commitments.clone(),
            validity_condition: vec![],
        };

        let l1_hash = batch_proof_output.da_slot_hash.into();

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

        let excluded_commitment_indices = batch_proof_output.preproven_commitments.clone();
        let filtered_commitments: Vec<SequencerCommitment> = commitments_on_da_slot
            .into_iter()
            .enumerate()
            .filter(|(index, _)| !excluded_commitment_indices.contains(index))
            .map(|(_, commitment)| commitment.clone())
            .collect();

        let l2_height = filtered_commitments
            [batch_proof_output.sequencer_commitments_range.0 as usize]
            .l2_start_block_number;
        // Fetch the block prior to the one at l2_height so compare state roots

        let prior_soft_confirmation_post_state_root = self
            .ledger_db
            .get_l2_state_root::<StateRoot>(l2_height - 1)?
            .ok_or_else(|| {
                anyhow!(
                "Proof verification: Could not find state root for L2 height: {}. Skipping proof.",
                l2_height - 1
            )
            })?;

        if prior_soft_confirmation_post_state_root.as_ref()
            != batch_proof_output.initial_state_root.as_ref()
        {
            return Err(anyhow!(
                    "Proof verification: For a known and verified sequencer commitment. Pre state root mismatch - expected 0x{} but got 0x{}. Skipping proof.",
                    hex::encode(&prior_soft_confirmation_post_state_root),
                    hex::encode(&batch_proof_output.initial_state_root)
                ).into());
        }

        for commitment in filtered_commitments
            .iter()
            .skip(batch_proof_output.sequencer_commitments_range.0 as usize)
            .take(
                (batch_proof_output.sequencer_commitments_range.1
                    - batch_proof_output.sequencer_commitments_range.0
                    + 1) as usize,
            )
        {
            let l2_start_height = commitment.l2_start_block_number;
            let l2_end_height = commitment.l2_end_block_number;
            for i in l2_start_height..=l2_end_height {
                self.ledger_db
                    .put_soft_confirmation_status(BatchNumber(i), SoftConfirmationStatus::Proven)?;
            }
        }
        // store in ledger db
        self.ledger_db.update_verified_proof_data(
            l1_block.header().height(),
            proof.clone(),
            stored_batch_proof_output,
        )?;
        Ok(())
    }
}

async fn sync_l1<Da>(
    start_l1_height: u64,
    da_service: Arc<Da>,
    sender: mpsc::Sender<Da::FilteredBlock>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
) where
    Da: DaService,
{
    let mut l1_height = start_l1_height;
    info!("Starting to sync from L1 height {}", l1_height);

    'block_sync: loop {
        // TODO: for a node, the da block at slot_height might not have been finalized yet
        // should wait for it to be finalized
        let last_finalized_l1_block_header =
            match da_service.get_last_finalized_block_header().await {
                Ok(header) => header,
                Err(e) => {
                    error!("Could not fetch last finalized L1 block header: {}", e);
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

        let new_l1_height = last_finalized_l1_block_header.height();

        for block_number in l1_height + 1..=new_l1_height {
            let l1_block =
                match get_da_block_at_height(&da_service, block_number, l1_block_cache.clone())
                    .await
                {
                    Ok(block) => block,
                    Err(e) => {
                        error!("Could not fetch last finalized L1 block: {}", e);
                        sleep(Duration::from_secs(2)).await;
                        continue 'block_sync;
                    }
                };

            if block_number > l1_height {
                l1_height = block_number;
                if let Err(e) = sender.send(l1_block).await {
                    error!("Could not notify about L1 block: {}", e);
                    continue 'block_sync;
                }
            }
        }

        sleep(Duration::from_secs(2)).await;
    }
}
