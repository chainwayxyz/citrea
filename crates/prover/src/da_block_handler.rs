use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::RangeInclusive;
use std::sync::Arc;

use anyhow::anyhow;
use bitcoin_da::helpers::compression::compress_blob;
use borsh::{BorshDeserialize, BorshSerialize};
use citrea_primitives::utils::{filter_out_proven_commitments, merge_state_diffs};
use citrea_primitives::{get_da_block_at_height, L1BlockCache, MAX_TXBODY_SIZE};
use rand::Rng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_db::ledger_db::ProverLedgerOps;
use sov_db::schema::types::{BatchNumber, SlotNumber, StoredProof, StoredStateTransition};
use sov_modules_api::{BlobReaderTrait, DaSpec, SignedSoftConfirmation, StateDiff, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, DaDataBatchProof, SequencerCommitment};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::{Proof, StateTransitionData, ZkvmHost};
use sov_stf_runner::{ProverConfig, ProverService};
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

type CommitmentStateTransitionData<Witness, Da> = (
    VecDeque<Vec<Witness>>,
    VecDeque<Vec<SignedSoftConfirmation>>,
    VecDeque<Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader>>,
);

pub(crate) struct L1BlockHandler<Vm, Da, Ps, DB, StateRoot, Witness>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: ProverLedgerOps,
    Ps: ProverService<Vm>,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
    Witness: Default + BorshDeserialize + Serialize + DeserializeOwned,
{
    prover_config: ProverConfig,
    prover_service: Arc<Ps>,
    ledger_db: DB,
    da_service: Arc<Da>,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    skip_submission_until_l1: u64,
    pending_l1_blocks: VecDeque<<Da as DaService>::FilteredBlock>,
    _state_root: PhantomData<StateRoot>,
    _witness: PhantomData<Witness>,
}

impl<Vm, Da, Ps, DB, StateRoot, Witness> L1BlockHandler<Vm, Da, Ps, DB, StateRoot, Witness>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<Vm, DaService = Da, StateRoot = StateRoot, Witness = Witness>,
    DB: ProverLedgerOps + Clone,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
    Witness: Default + BorshDeserialize + Serialize + DeserializeOwned,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prover_config: ProverConfig,
        prover_service: Arc<Ps>,
        ledger_db: DB,
        da_service: Arc<Da>,
        sequencer_pub_key: Vec<u8>,
        sequencer_da_pub_key: Vec<u8>,
        code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
        skip_submission_until_l1: u64,
        l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    ) -> Self {
        Self {
            prover_config,
            prover_service,
            ledger_db,
            da_service,
            sequencer_pub_key,
            sequencer_da_pub_key,
            code_commitments_by_spec,
            skip_submission_until_l1,
            l1_block_cache,
            pending_l1_blocks: VecDeque::new(),
            _state_root: PhantomData,
            _witness: PhantomData,
        }
    }

    pub async fn run(mut self, start_l1_height: u64) {
        if let Err(e) = self.check_and_recover_ongoing_proving_sessions().await {
            error!("Failed to recover ongoing proving sessions: {:?}", e);
        }

        let (l1_tx, mut l1_rx) = mpsc::channel(1);
        let l1_sync_worker = sync_l1(
            start_l1_height,
            self.da_service.clone(),
            l1_tx,
            self.l1_block_cache.clone(),
        );
        tokio::pin!(l1_sync_worker);

        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;
        loop {
            select! {
                _ = &mut l1_sync_worker => {},
                Some(l1_block) = l1_rx.recv() => {
                    self.pending_l1_blocks.push_back(l1_block);
                },
                _ = interval.tick() => {
                    if let Err(e) = self.process_l1_block().await {
                        error!("Could not process L1 block and generate proof: {:?}", e);
                    }
                },
            }
        }
    }

    async fn process_l1_block(&mut self) -> Result<(), anyhow::Error> {
        while !self.pending_l1_blocks.is_empty() {
            let l1_block = self
                .pending_l1_blocks
                .front()
                .expect("Pending l1 blocks cannot be empty");
            // work on the first unprocessed l1 block
            let l1_height = l1_block.header().height();

            // Set the l1 height of the l1 hash
            self.ledger_db
                .set_l1_height_of_l1_hash(
                    l1_block.header().hash().into(),
                    l1_block.header().height(),
                )
                .unwrap();

            let mut da_data: Vec<<<Da as DaService>::Spec as DaSpec>::BlobTransaction> =
                self.da_service.extract_relevant_blobs(l1_block);

            // if we don't do this, the zk circuit can't read the sequencer commitments
            da_data.iter_mut().for_each(|blob| {
                blob.full_data();
            });
            let mut sequencer_commitments: Vec<SequencerCommitment> =
                self.extract_sequencer_commitments(l1_block.header().hash().into(), &mut da_data);

            if sequencer_commitments.is_empty() {
                info!("No sequencer commitment found at height {}", l1_height,);
                self.ledger_db
                    .set_last_scanned_l1_height(SlotNumber(l1_height))
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to put prover last scanned l1 height in the ledger db {}",
                            l1_height
                        )
                    });

                self.pending_l1_blocks.pop_front();
                continue;
            }

            info!(
                "Processing {} sequencer commitments at height {}",
                sequencer_commitments.len(),
                l1_block.header().height(),
            );

            // Make sure all sequencer commitments are stored in ascending order.
            // We sort before checking ranges to prevent substraction errors.
            sequencer_commitments.sort();

            // If the L2 range does not exist, we break off the local loop getting back to
            // the outer loop / select to make room for other tasks to run.
            // We retry the L1 block there as well.
            if !self.check_l2_range_exists(
                sequencer_commitments[0].l2_start_block_number,
                sequencer_commitments[sequencer_commitments.len() - 1].l2_end_block_number,
            ) {
                break;
            }

            // if proof_sampling_number is 0, then we always prove and submit
            // otherwise we submit and prove with a probability of 1/proof_sampling_number
            let should_prove = self.prover_config.proof_sampling_number == 0
                || rand::thread_rng().gen_range(0..self.prover_config.proof_sampling_number) == 0;

            let (sequencer_commitments, preproven_commitments) =
                filter_out_proven_commitments(&self.ledger_db, &sequencer_commitments)?;

            if sequencer_commitments.is_empty() {
                info!(
                    "All sequencer commitments are duplicates from a former DA block {}",
                    l1_height
                );
                self.ledger_db
                    .set_last_scanned_l1_height(SlotNumber(l1_height))
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to put prover last scanned l1 height in the ledger db {}",
                            l1_height
                        )
                    });

                self.pending_l1_blocks.pop_front();
                continue;
            }

            let da_block_header_of_commitments: <<Da as DaService>::Spec as DaSpec>::BlockHeader =
                l1_block.header().clone();

            let hash = da_block_header_of_commitments.hash();

            if should_prove {
                let sequencer_commitments_groups =
                    self.break_sequencer_commitments_into_groups(&sequencer_commitments)?;

                let submitted_proofs = self
                    .ledger_db
                    .get_proofs_by_l1_height(l1_height)?
                    .unwrap_or(vec![]);
                for sequencer_commitment_range in sequencer_commitments_groups {
                    // There is no ongoing bonsai session to recover
                    let transition_data: StateTransitionData<StateRoot, Witness, Da::Spec> = self
                        .create_state_transition_data(
                            &sequencer_commitments,
                            sequencer_commitment_range,
                            &preproven_commitments,
                            da_block_header_of_commitments.clone(),
                            da_data.clone(),
                            l1_block,
                        )
                        .await?;

                    // check if transition data is already proven by crash recovery
                    if !self.state_transition_already_proven(&transition_data, &submitted_proofs) {
                        self.prove_state_transition(
                            transition_data,
                            self.skip_submission_until_l1,
                            l1_height,
                            hash.clone(),
                        )
                        .await?;
                    }

                    self.save_commitments(&sequencer_commitments, l1_height);
                }
            }

            if let Err(e) = self
                .ledger_db
                .set_last_scanned_l1_height(SlotNumber(l1_height))
            {
                panic!(
                    "Failed to put prover last scanned l1 height in the ledger db: {}",
                    e
                );
            }

            self.pending_l1_blocks.pop_front();
        }
        Ok(())
    }

    fn extract_sequencer_commitments(
        &self,
        l1_block_hash: [u8; 32],
        da_data: &mut [<<Da as DaService>::Spec as DaSpec>::BlobTransaction],
    ) -> Vec<SequencerCommitment> {
        let mut sequencer_commitments = vec![];
        // if we don't do this, the zk circuit can't read the sequencer commitments
        da_data.iter_mut().for_each(|blob| {
            blob.full_data();
        });
        da_data.iter_mut().for_each(|tx| {
            let data = DaDataBatchProof::try_from_slice(tx.full_data());
            // Check for commitment
            if tx.sender().as_ref() == self.sequencer_da_pub_key.as_slice() {
                if let Ok(DaDataBatchProof::SequencerCommitment(seq_com)) = data {
                    sequencer_commitments.push(seq_com);
                } else {
                    tracing::warn!(
                        "Found broken DA data in block 0x{}: {:?}",
                        hex::encode(l1_block_hash),
                        data
                    );
                }
            }
        });
        sequencer_commitments
    }

    fn check_l2_range_exists(&self, first_l2_height_of_l1: u64, last_l2_height_of_l1: u64) -> bool {
        let ledger_db = &self.ledger_db.clone();
        if let Ok(range) = ledger_db.clone().get_soft_confirmation_range(
            &(BatchNumber(first_l2_height_of_l1)..BatchNumber(last_l2_height_of_l1 + 1)),
        ) {
            if (range.len() as u64) >= (last_l2_height_of_l1 - first_l2_height_of_l1 + 1) {
                return true;
            }
        }
        false
    }

    fn break_sequencer_commitments_into_groups(
        &self,
        sequencer_commitments: &[SequencerCommitment],
    ) -> anyhow::Result<Vec<RangeInclusive<usize>>> {
        let mut result_range = vec![];

        let mut range = 0usize..=0usize;
        let mut cumulative_state_diff = StateDiff::new();
        for (index, sequencer_commitment) in sequencer_commitments.iter().enumerate() {
            let mut sequencer_commitment_state_diff = StateDiff::new();
            for l2_height in sequencer_commitment.l2_start_block_number
                ..=sequencer_commitment.l2_end_block_number
            {
                let state_diff = self
                    .ledger_db
                    .get_l2_state_diff(BatchNumber(l2_height))?
                    .ok_or(anyhow!(
                        "Could not find state diff for L2 range {}-{}",
                        sequencer_commitment.l2_start_block_number,
                        sequencer_commitment.l2_end_block_number
                    ))?;
                sequencer_commitment_state_diff =
                    merge_state_diffs(sequencer_commitment_state_diff, state_diff);
            }
            cumulative_state_diff = merge_state_diffs(
                cumulative_state_diff,
                sequencer_commitment_state_diff.clone(),
            );

            let compressed_state_diff = compress_blob(&borsh::to_vec(&cumulative_state_diff)?);

            // Threshold is checked by comparing compressed state diff size as the data will be compressed before it is written on DA
            let state_diff_threshold_reached =
                compressed_state_diff.len() as u64 > MAX_TXBODY_SIZE.try_into().unwrap();

            if state_diff_threshold_reached {
                // We've exceeded the limit with the current commitments
                // so we have to stop at the previous one.
                result_range.push(range);

                // Reset the cumulative state diff to be equal to the current commitment state diff
                cumulative_state_diff = sequencer_commitment_state_diff;
                range = index..=index;
            } else {
                range = *range.start()..=index;
            }
        }

        // If the last group hasn't been reset because it has not reached the threshold,
        // Add it anyway
        result_range.push(range);
        Ok(result_range)
    }

    async fn create_state_transition_data(
        &self,
        sequencer_commitments: &[SequencerCommitment],
        sequencer_commitments_range: RangeInclusive<usize>,
        preproven_commitments: &[usize],
        da_block_header_of_commitments: <<Da as DaService>::Spec as DaSpec>::BlockHeader,
        da_data: Vec<<<Da as DaService>::Spec as DaSpec>::BlobTransaction>,
        l1_block: &Da::FilteredBlock,
    ) -> Result<StateTransitionData<StateRoot, Witness, Da::Spec>, anyhow::Error> {
        let first_l2_height_of_l1 =
            sequencer_commitments[*sequencer_commitments_range.start()].l2_start_block_number;
        let last_l2_height_of_l1 =
            sequencer_commitments[*sequencer_commitments_range.end()].l2_end_block_number;
        let (
            state_transition_witnesses,
            soft_confirmations,
            da_block_headers_of_soft_confirmations,
        ) = self
            .get_state_transition_data_from_commitments(
                &sequencer_commitments[sequencer_commitments_range.clone()],
                &self.da_service,
            )
            .await?;
        let initial_state_root = self
            .ledger_db
            .get_l2_state_root::<StateRoot>(first_l2_height_of_l1 - 1)?
            .expect("There should be a state root");
        let initial_batch_hash = self
            .ledger_db
            .get_soft_confirmation_by_number(&BatchNumber(first_l2_height_of_l1))?
            .ok_or(anyhow!(
                "Could not find soft batch at height {}",
                first_l2_height_of_l1
            ))?
            .prev_hash;

        let final_state_root = self
            .ledger_db
            .get_l2_state_root::<StateRoot>(last_l2_height_of_l1)?
            .expect("There should be a state root");

        let (inclusion_proof, completeness_proof) = self
            .da_service
            .get_extraction_proof(l1_block, &da_data)
            .await;

        let transition_data: StateTransitionData<StateRoot, Witness, Da::Spec> =
            StateTransitionData {
                initial_state_root,
                final_state_root,
                initial_batch_hash,
                da_data,
                da_block_header_of_commitments,
                inclusion_proof,
                completeness_proof,
                soft_confirmations,
                state_transition_witnesses,
                da_block_headers_of_soft_confirmations,
                preproven_commitments: preproven_commitments.to_vec(),
                sequencer_commitments_range: (
                    *sequencer_commitments_range.start() as u32,
                    *sequencer_commitments_range.end() as u32,
                ),
                sequencer_public_key: self.sequencer_pub_key.clone(),
                sequencer_da_public_key: self.sequencer_da_pub_key.clone(),
            };
        Ok(transition_data)
    }

    async fn get_state_transition_data_from_commitments(
        &self,
        sequencer_commitments: &[SequencerCommitment],
        da_service: &Arc<Da>,
    ) -> Result<CommitmentStateTransitionData<Witness, Da>, anyhow::Error> {
        let mut state_transition_witnesses: VecDeque<Vec<Witness>> = VecDeque::new();
        let mut soft_confirmations: VecDeque<Vec<SignedSoftConfirmation>> = VecDeque::new();
        let mut da_block_headers_of_soft_confirmations: VecDeque<
            Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader>,
        > = VecDeque::new();
        for sequencer_commitment in sequencer_commitments.to_owned().iter() {
            // get the l2 height ranges of each seq_commitments
            let mut witnesses = vec![];
            let start_l2 = sequencer_commitment.l2_start_block_number;
            let end_l2 = sequencer_commitment.l2_end_block_number;
            let soft_confirmations_in_commitment = match self
                .ledger_db
                .get_soft_confirmation_range(&(BatchNumber(start_l2)..BatchNumber(end_l2 + 1)))
            {
                Ok(soft_confirmations) => soft_confirmations,
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to get soft confirmations from the ledger db: {}",
                        e
                    ));
                }
            };
            let mut commitment_soft_confirmations = vec![];
            let mut da_block_headers_to_push: Vec<
                <<Da as DaService>::Spec as DaSpec>::BlockHeader,
            > = vec![];
            for soft_confirmation in soft_confirmations_in_commitment {
                if da_block_headers_to_push.is_empty()
                    || da_block_headers_to_push.last().unwrap().height()
                        != soft_confirmation.da_slot_height
                {
                    let filtered_block = match get_da_block_at_height(
                        da_service,
                        soft_confirmation.da_slot_height,
                        self.l1_block_cache.clone(),
                    )
                    .await
                    {
                        Ok(block) => block,
                        Err(_) => {
                            return Err(anyhow!(
                                "Error while fetching DA block at height: {}",
                                soft_confirmation.da_slot_height
                            ));
                        }
                    };
                    da_block_headers_to_push.push(filtered_block.header().clone());
                }
                let signed_soft_confirmation: SignedSoftConfirmation =
                    soft_confirmation.clone().into();
                commitment_soft_confirmations.push(signed_soft_confirmation.clone());
            }
            soft_confirmations.push_back(commitment_soft_confirmations);

            da_block_headers_of_soft_confirmations.push_back(da_block_headers_to_push);
            for l2_height in sequencer_commitment.l2_start_block_number
                ..=sequencer_commitment.l2_end_block_number
            {
                let witness = match self.ledger_db.get_l2_witness::<Witness>(l2_height) {
                    Ok(witness) => witness,
                    Err(e) => {
                        return Err(anyhow!("Failed to get witness from the ledger db: {}", e))
                    }
                };

                witnesses.push(witness.expect("A witness must be present"));
            }
            state_transition_witnesses.push_back(witnesses);
        }
        Ok((
            state_transition_witnesses,
            soft_confirmations,
            da_block_headers_of_soft_confirmations,
        ))
    }

    async fn prove_state_transition(
        &self,
        transition_data: StateTransitionData<StateRoot, Witness, Da::Spec>,
        skip_submission_until_l1: u64,
        l1_height: u64,
        hash: <<Da as DaService>::Spec as DaSpec>::SlotHash,
    ) -> Result<(), anyhow::Error> {
        // Skip submission until l1 height
        if l1_height >= skip_submission_until_l1 {
            self.generate_and_submit_proof(transition_data, hash)
                .await?;
        } else {
            info!("Skipping proving for l1 height {}", l1_height);
        }
        Ok(())
    }

    async fn generate_and_submit_proof(
        &self,
        transition_data: StateTransitionData<StateRoot, Witness, Da::Spec>,
        hash: <<Da as DaService>::Spec as DaSpec>::SlotHash,
    ) -> Result<(), anyhow::Error> {
        let prover_service = self.prover_service.as_ref();

        prover_service.submit_witness(transition_data).await;

        prover_service.prove(hash.clone()).await?;

        let (tx_id, proof) = match prover_service
            .wait_for_proving_and_send_to_da(hash.clone(), &self.da_service)
            .await
        {
            Ok((tx_id, proof)) => (tx_id, proof),
            Err(e) => {
                return Err(anyhow!("Failed to prove and send to DA: {}", e));
            }
        };

        self.extract_and_store_proof(tx_id, proof).await
    }

    fn state_transition_already_proven(
        &self,
        state_transition: &StateTransitionData<StateRoot, Witness, Da::Spec>,
        proofs: &Vec<StoredProof>,
    ) -> bool {
        for proof in proofs {
            if proof.state_transition.initial_state_root
                == state_transition.initial_state_root.as_ref()
                && proof.state_transition.final_state_root
                    == state_transition.final_state_root.as_ref()
                && proof.state_transition.sequencer_commitments_range
                    == state_transition.sequencer_commitments_range
            {
                return true;
            }
        }
        false
    }

    fn save_commitments(&self, sequencer_commitments: &[SequencerCommitment], l1_height: u64) {
        for sequencer_commitment in sequencer_commitments.iter() {
            // Save commitments on prover ledger db
            self.ledger_db
                .update_commitments_on_da_slot(l1_height, sequencer_commitment.clone())
                .unwrap();

            let l2_start_height = sequencer_commitment.l2_start_block_number;
            let l2_end_height = sequencer_commitment.l2_end_block_number;
            for i in l2_start_height..=l2_end_height {
                self.ledger_db
                    .put_soft_confirmation_status(BatchNumber(i), SoftConfirmationStatus::Proven)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to put soft confirmation status in the ledger db {}",
                            i
                        )
                    });
            }
        }
    }

    async fn extract_and_store_proof(
        &self,
        tx_id: <Da as DaService>::TransactionId,
        proof: Proof,
    ) -> Result<(), anyhow::Error> {
        let tx_id_u8 = tx_id.into();

        // l1_height => (tx_id, proof, transition_data)
        // save proof along with tx id to db, should be queriable by slot number or slot hash
        let transition_data = Vm::extract_output::<<Da as DaService>::Spec, StateRoot>(&proof)
            .expect("Proof should be deserializable");

        match &proof {
            Proof::PublicInput(_) => {
                warn!("Proof is public input, skipping");
            }
            Proof::Full(data) => {
                info!("Verifying proof!");
                let code_commitment = self
                    .code_commitments_by_spec
                    .get(&transition_data.last_active_spec_id)
                    .expect("Proof public input must contain valid spec id");
                Vm::verify(data, code_commitment)
                    .map_err(|err| anyhow!("Failed to verify proof: {:?}. Skipping it...", err))?;
            }
        }

        info!("transition data: {:?}", transition_data);

        let slot_hash = transition_data.da_slot_hash.into();

        let stored_state_transition = StoredStateTransition {
            initial_state_root: transition_data.initial_state_root.as_ref().to_vec(),
            final_state_root: transition_data.final_state_root.as_ref().to_vec(),
            state_diff: transition_data.state_diff,
            da_slot_hash: slot_hash,
            sequencer_commitments_range: transition_data.sequencer_commitments_range,
            sequencer_public_key: transition_data.sequencer_public_key,
            sequencer_da_public_key: transition_data.sequencer_da_public_key,
            preproven_commitments: transition_data.preproven_commitments,
            validity_condition: borsh::to_vec(&transition_data.validity_condition).unwrap(),
        };
        let l1_height = self
            .ledger_db
            .get_l1_height_of_l1_hash(slot_hash)?
            .expect("l1 height should exist");

        if let Err(e) = self.ledger_db.insert_proof_data_by_l1_height(
            l1_height,
            tx_id_u8,
            proof,
            stored_state_transition,
        ) {
            panic!("Failed to put proof data in the ledger db: {}", e);
        }
        Ok(())
    }

    async fn check_and_recover_ongoing_proving_sessions(&self) -> Result<(), anyhow::Error> {
        let prover_service = self.prover_service.as_ref();
        let results = prover_service
            .recover_proving_sessions_and_send_to_da(&self.da_service)
            .await?;

        for (tx_id, proof) in results {
            self.extract_and_store_proof(tx_id, proof).await?;
        }
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
