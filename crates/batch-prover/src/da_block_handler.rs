use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::RangeInclusive;
use std::sync::Arc;

use anyhow::{anyhow, Context as _};
use borsh::{BorshDeserialize, BorshSerialize};
use citrea_common::cache::L1BlockCache;
use citrea_common::da::get_da_block_at_height;
use citrea_common::utils::merge_state_diffs;
use citrea_common::BatchProverConfig;
use citrea_primitives::compression::compress_blob;
use citrea_primitives::forks::FORKS;
use citrea_primitives::MAX_TXBODY_SIZE;
use rand::Rng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::{BatchNumber, SlotNumber};
use sov_modules_api::fork::fork_from_block_number;
use sov_modules_api::{DaSpec, StateDiff, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::ProverService;
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::errors::L1ProcessingError;
use crate::metrics::BATCH_PROVER_METRICS;
use crate::proving::{data_to_prove, extract_and_store_proof, prove_l1, GroupCommitments};

type CommitmentStateTransitionData<'txs, Witness, Da, Tx> = (
    VecDeque<Vec<(Witness, Witness)>>,
    VecDeque<Vec<SignedSoftConfirmation<'txs, Tx>>>,
    VecDeque<Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader>>,
);

pub(crate) struct L1BlockHandler<Vm, Da, Ps, DB, StateRoot, Witness, Tx>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: BatchProverLedgerOps,
    Ps: ProverService,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
    Witness: Default + BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned,
{
    prover_config: BatchProverConfig,
    prover_service: Arc<Ps>,
    ledger_db: DB,
    da_service: Arc<Da>,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    elfs_by_spec: HashMap<SpecId, Vec<u8>>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    skip_submission_until_l1: u64,
    pending_l1_blocks: VecDeque<<Da as DaService>::FilteredBlock>,
    _state_root: PhantomData<StateRoot>,
    _witness: PhantomData<Witness>,
    _tx: PhantomData<Tx>,
}

impl<Vm, Da, Ps, DB, StateRoot, Witness, Tx> L1BlockHandler<Vm, Da, Ps, DB, StateRoot, Witness, Tx>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<DaService = Da>,
    DB: BatchProverLedgerOps + Clone + 'static,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
    Witness: Default + BorshDeserialize + BorshSerialize + Serialize + DeserializeOwned,
    Tx: Clone + BorshDeserialize + BorshSerialize,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prover_config: BatchProverConfig,
        prover_service: Arc<Ps>,
        ledger_db: DB,
        da_service: Arc<Da>,
        sequencer_pub_key: Vec<u8>,
        sequencer_da_pub_key: Vec<u8>,
        code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
        elfs_by_spec: HashMap<SpecId, Vec<u8>>,
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
            elfs_by_spec,
            skip_submission_until_l1,
            l1_block_cache,
            pending_l1_blocks: VecDeque::new(),
            _state_root: PhantomData,
            _witness: PhantomData,
            _tx: PhantomData,
        }
    }

    pub async fn run(mut self, start_l1_height: u64, cancellation_token: CancellationToken) {
        if self.prover_config.enable_recovery {
            if let Err(e) = self.check_and_recover_ongoing_proving_sessions().await {
                error!("Failed to recover ongoing proving sessions: {:?}", e);
            }
        } else {
            // If recovery is disabled, clear pending proving sessions
            self.ledger_db
                .clear_pending_proving_sessions()
                .expect("Failed to clear pending proving sessions");
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
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                }
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

            let data_to_prove = data_to_prove::<Da, DB, StateRoot, Witness, Tx>(
                self.da_service.clone(),
                self.ledger_db.clone(),
                self.sequencer_pub_key.clone(),
                self.sequencer_da_pub_key.clone(),
                self.l1_block_cache.clone(),
                l1_block,
                Some(GroupCommitments::Normal),
            )
            .await;

            let (sequencer_commitments, inputs) = match data_to_prove {
                Ok((commitments, inputs)) => (commitments, inputs),
                Err(e) => match e {
                    L1ProcessingError::NoSeqCommitments { l1_height } => {
                        info!("No sequencer commitment found at height {}", l1_height,);
                        self.ledger_db
                            .set_last_scanned_l1_height(SlotNumber(l1_height))
                            .unwrap_or_else(|_| panic!("Failed to put prover last scanned l1 height in the ledger db {}", l1_height));

                        self.pending_l1_blocks.pop_front();
                        continue;
                    }
                    L1ProcessingError::DuplicateCommitments { l1_height } => {
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
                    L1ProcessingError::L2RangeMissing {
                        start_block_number,
                        end_block_number,
                    } => {
                        warn!("L2 range of commitments is not synced yet: {start_block_number} - {end_block_number}");
                        break;
                    }
                    L1ProcessingError::Other(msg) => {
                        error!("{msg}");
                        return Err(anyhow!("{}", msg));
                    }
                },
            };

            info!(
                "Processing {} sequencer commitments at height {}",
                sequencer_commitments.len(),
                l1_block.header().height(),
            );

            // if proof_sampling_number is 0, then we always prove and submit
            // otherwise we submit and prove with a probability of 1/proof_sampling_number
            let should_prove = self.prover_config.proof_sampling_number == 0
                || rand::thread_rng().gen_range(0..self.prover_config.proof_sampling_number) == 0;

            if should_prove {
                if l1_height >= self.skip_submission_until_l1 {
                    prove_l1::<Da, Ps, Vm, DB, StateRoot, Witness, Tx>(
                        self.prover_service.clone(),
                        self.ledger_db.clone(),
                        self.code_commitments_by_spec.clone(),
                        self.elfs_by_spec.clone(),
                        l1_block,
                        sequencer_commitments,
                        inputs,
                    )
                    .await?;
                } else {
                    info!("Skipping proving for l1 height {}", l1_height);
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

            BATCH_PROVER_METRICS.current_l1_block.set(l1_height as f64);

            self.pending_l1_blocks.pop_front();
        }
        Ok(())
    }

    async fn check_and_recover_ongoing_proving_sessions(&self) -> Result<(), anyhow::Error> {
        let prover_service = self.prover_service.as_ref();
        let txs_and_proofs = prover_service.recover_and_submit_proving_sessions().await?;

        extract_and_store_proof::<DB, Da, Vm, StateRoot>(
            self.ledger_db.clone(),
            txs_and_proofs,
            self.code_commitments_by_spec.clone(),
        )
        .await?;

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

pub(crate) async fn get_batch_proof_circuit_input_from_commitments<
    'txs,
    Da: DaService,
    DB: BatchProverLedgerOps,
    Witness: DeserializeOwned,
    Tx: Clone + BorshDeserialize + 'txs,
>(
    sequencer_commitments: &[SequencerCommitment],
    da_service: &Arc<Da>,
    ledger_db: &DB,
    l1_block_cache: &Arc<Mutex<L1BlockCache<Da>>>,
) -> Result<CommitmentStateTransitionData<'txs, Witness, Da, Tx>, anyhow::Error> {
    let mut state_transition_witnesses: VecDeque<Vec<(Witness, Witness)>> = VecDeque::new();
    let mut soft_confirmations: VecDeque<Vec<SignedSoftConfirmation<Tx>>> = VecDeque::new();
    let mut da_block_headers_of_soft_confirmations: VecDeque<
        Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader>,
    > = VecDeque::new();
    for sequencer_commitment in sequencer_commitments.to_owned().iter() {
        // get the l2 height ranges of each seq_commitments
        let mut witnesses = vec![];
        let start_l2 = sequencer_commitment.l2_start_block_number;
        let end_l2 = sequencer_commitment.l2_end_block_number;
        let soft_confirmations_in_commitment = match ledger_db
            .get_soft_confirmation_range(&(BatchNumber(start_l2)..=BatchNumber(end_l2)))
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
        let mut da_block_headers_to_push: Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader> =
            vec![];
        for soft_confirmation in soft_confirmations_in_commitment {
            if da_block_headers_to_push.is_empty()
                || da_block_headers_to_push.last().unwrap().height()
                    != soft_confirmation.da_slot_height
            {
                let filtered_block = match get_da_block_at_height(
                    da_service,
                    soft_confirmation.da_slot_height,
                    l1_block_cache.clone(),
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
            let signed_soft_confirmation: SignedSoftConfirmation<Tx> = soft_confirmation
                .try_into()
                .context("Failed to parse transactions")?;
            commitment_soft_confirmations.push(signed_soft_confirmation);
        }
        soft_confirmations.push_back(commitment_soft_confirmations);

        da_block_headers_of_soft_confirmations.push_back(da_block_headers_to_push);
        for l2_height in
            sequencer_commitment.l2_start_block_number..=sequencer_commitment.l2_end_block_number
        {
            let (state_witness, offchain_witness) = match ledger_db
                .get_l2_witness::<Witness>(l2_height)
            {
                Ok(inner) => inner.expect("Witnesses must be present"),
                Err(e) => return Err(anyhow!("Failed to get witness from the ledger db: {}", e)),
            };

            witnesses.push((state_witness, offchain_witness));
        }
        state_transition_witnesses.push_back(witnesses);
    }
    Ok((
        state_transition_witnesses,
        soft_confirmations,
        da_block_headers_of_soft_confirmations,
    ))
}

pub(crate) fn break_sequencer_commitments_into_groups<DB: BatchProverLedgerOps>(
    ledger_db: &DB,
    sequencer_commitments: &[SequencerCommitment],
) -> anyhow::Result<Vec<RangeInclusive<usize>>> {
    let mut result_range = vec![];

    // This assumes that sequencer commitments are sorted.
    let first_block_number = sequencer_commitments
        .first()
        .ok_or(anyhow!("No Sequencer commitments found"))?
        .l2_start_block_number;
    let mut current_spec = fork_from_block_number(FORKS, first_block_number).spec_id;

    let mut range = 0usize..=0usize;
    let mut cumulative_state_diff = StateDiff::new();
    for (index, sequencer_commitment) in sequencer_commitments.iter().enumerate() {
        let mut sequencer_commitment_state_diff = StateDiff::new();
        for l2_height in
            sequencer_commitment.l2_start_block_number..=sequencer_commitment.l2_end_block_number
        {
            let state_diff =
                ledger_db
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
        let state_diff_threshold_reached = compressed_state_diff.len() > MAX_TXBODY_SIZE;

        let commitment_spec =
            fork_from_block_number(FORKS, sequencer_commitment.l2_end_block_number).spec_id;

        if commitment_spec != current_spec || state_diff_threshold_reached {
            result_range.push(range);
            // Reset the cumulative state diff to be equal to the current commitment state diff
            cumulative_state_diff = sequencer_commitment_state_diff;
            range = index..=index;
            current_spec = commitment_spec
        } else {
            range = *range.start()..=index;
        }
    }

    // If the last group hasn't been reset because it has not reached the threshold,
    // Add it anyway
    result_range.push(range);
    Ok(result_range)
}
