use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use citrea_common::cache::L1BlockCache;
use citrea_common::da::{extract_sequencer_commitments, get_da_block_at_height};
use citrea_common::utils::{check_l2_block_exists, filter_out_proven_commitments};
use citrea_primitives::forks::fork_from_block_number;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use prover_services::{ParallelProverService, ProofData};
use serde::{Deserialize, Serialize};
use short_header_proof_provider::SHORT_HEADER_PROOF_PROVIDER;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::batch_proof::{StoredBatchProof, StoredBatchProofOutput};
use sov_db::schema::types::SoftConfirmationNumber;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{L2Block, SlotData, SpecId, Zkvm};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::{BlockHeaderTrait, DaNamespace, DaSpec, SequencerCommitment};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::batch_proof::input::v1::BatchProofCircuitInputV1;
use sov_rollup_interface::zk::batch_proof::input::BatchProofCircuitInput;
use sov_rollup_interface::zk::batch_proof::output::v1::BatchProofCircuitOutputV1;
use sov_rollup_interface::zk::batch_proof::output::v2::BatchProofCircuitOutputV2;
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use sov_state::Witness;
use tokio::sync::Mutex;
use tracing::level_filters::LevelFilter;
use tracing::{debug, info};
use tracing_subscriber::layer::SubscriberExt;

use crate::da_block_handler::break_sequencer_commitments_into_groups;
use crate::errors::L1ProcessingError;

const MAX_CUMULATIVE_CACHE_SIZE: usize = 128 * 1024 * 1024;

type CommitmentStateTransitionData<'txs, Da> = (
    VecDeque<Vec<u8>>,
    VecDeque<Vec<(Witness, Witness)>>,
    Vec<u64>,
    VecDeque<Vec<L2Block<'txs, Transaction>>>,
    VecDeque<Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader>>,
    Witness,
);

#[derive(Debug, Clone, Deserialize, Serialize)]
/// Enum to determine how to group commitments
pub enum GroupCommitments {
    /// Groups commitments the normal way
    /// Generates proof(s) given l1 height using the same strategy of batch prover
    Normal,
    /// Breaks all commitments into a single group and generates a single proof
    SingleShot,
    /// Every commitment is a group on their own
    /// Generates a proof for every commitment
    OneByOne,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn data_to_prove<'txs, Da, DB>(
    da_service: Arc<Da>,
    ledger: DB,
    storage_manager: &ProverStorageManager,
    sequencer_pub_key: Vec<u8>,
    sequencer_k256_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    l1_block: &<Da as DaService>::FilteredBlock,
    group_commitments: Option<GroupCommitments>,
) -> Result<
    (
        Vec<SequencerCommitment>,
        Vec<BatchProofCircuitInput<'txs, Da::Spec, Transaction>>,
    ),
    L1ProcessingError,
>
where
    Da: DaService,
    DB: BatchProverLedgerOps,
{
    let l1_height = l1_block.header().height();

    let (da_data, inclusion_proof, completeness_proof) =
        da_service.extract_relevant_blobs_with_proof(l1_block, DaNamespace::ToBatchProver);

    let sequencer_commitments: Vec<SequencerCommitment> =
        extract_sequencer_commitments::<Da>(da_service.clone(), l1_block, &sequencer_da_pub_key);

    if sequencer_commitments.is_empty() {
        return Err(L1ProcessingError::NoSeqCommitments {
            l1_height: l1_block.header().height(),
        });
    }

    // If the L2 range does not exist, we break off the local loop getting back to
    // the outer loop / select to make room for other tasks to run.
    // We retry the L1 block there as well.
    let start_block_number = sequencer_commitments[0].l2_start_block_number;
    let end_block_number =
        sequencer_commitments[sequencer_commitments.len() - 1].l2_end_block_number;

    // Verify that we have all l2 blocks synced to execute the commitment
    if !check_l2_block_exists(&ledger, end_block_number) {
        return Err(L1ProcessingError::L2RangeMissing {
            start_block_number,
            end_block_number,
        });
    }

    let (mut sequencer_commitments, preproven_commitments) =
        filter_out_proven_commitments(&ledger, &sequencer_commitments).map_err(|e| {
            L1ProcessingError::Other(format!("Error filtering out proven commitments: {}", e))
        })?;

    sequencer_commitments.sort();

    if sequencer_commitments.is_empty() {
        return Err(L1ProcessingError::DuplicateCommitments { l1_height });
    }

    let da_block_header_of_commitments: <<Da as DaService>::Spec as DaSpec>::BlockHeader =
        l1_block.header().clone();

    let ranges = match group_commitments {
        Some(GroupCommitments::SingleShot) => vec![(0..=sequencer_commitments.len() - 1)],
        Some(GroupCommitments::OneByOne) => sequencer_commitments
            .iter()
            .enumerate()
            .map(|(i, _)| (i..=i))
            .collect(),
        // Default behavior is the normal grouping
        _ => break_sequencer_commitments_into_groups(&ledger, &sequencer_commitments).map_err(
            |e| {
                L1ProcessingError::Other(format!(
                    "Error breaking sequencer commitments into groups: {:?}",
                    e
                ))
            },
        )?,
    };

    let mut batch_proof_circuit_inputs = Vec::with_capacity(ranges.len());

    for sequencer_commitments_range in ranges {
        let first_l2_height_of_l1 =
            sequencer_commitments[*sequencer_commitments_range.start()].l2_start_block_number;
        let last_l2_height_of_l1 =
            sequencer_commitments[*sequencer_commitments_range.end()].l2_end_block_number;

        tracing::info!(
            "Providing input for batch proof circuit for L1 block at height: {}, L2 range #{}-#{}",
            l1_height,
            first_l2_height_of_l1,
            last_l2_height_of_l1
        );

        let (
            short_header_proofs,
            state_transition_witnesses,
            cache_prune_l2_heights,
            l2_blocks,
            da_block_headers_of_l2_blocks,
            last_l1_hash_witness,
        ) = get_batch_proof_circuit_input_from_commitments(
            &sequencer_commitments[sequencer_commitments_range.clone()],
            &da_service,
            &ledger,
            &l1_block_cache,
            storage_manager,
            &sequencer_k256_pub_key,
            &sequencer_pub_key,
        )
        .await
        .map_err(|e| {
            L1ProcessingError::Other(format!(
                "Error getting state transition data from commitments: {:?}",
                e
            ))
        })?;
        let initial_state_root = ledger
            .get_l2_state_root(first_l2_height_of_l1 - 1)
            .map_err(|e| {
                L1ProcessingError::Other(format!("Error getting initial state root: {:?}", e))
            })?
            .expect("There should be a state root");

        let final_state_root = ledger
            .get_l2_state_root(last_l2_height_of_l1)
            .map_err(|e| {
                L1ProcessingError::Other(format!("Error getting final state root: {:?}", e))
            })?
            .expect("There should be a state root");

        let initial_soft_confirmation_hash = ledger
            .get_soft_confirmation_by_number(&SoftConfirmationNumber(first_l2_height_of_l1))
            .map_err(|e| {
                L1ProcessingError::Other(format!(
                    "Error getting initial soft confirmation hash: {:?}",
                    e
                ))
            })?
            .ok_or(L1ProcessingError::Other(format!(
                "Could not find soft confirmation at height {}",
                first_l2_height_of_l1
            )))?
            .prev_hash;

        let input = BatchProofCircuitInput {
            initial_state_root,
            da_data: da_data.clone(),
            da_block_header_of_commitments: da_block_header_of_commitments.clone(),
            inclusion_proof: inclusion_proof.clone(),
            completeness_proof: completeness_proof.clone(),
            l2_blocks,
            state_transition_witnesses,
            da_block_headers_of_l2_blocks,
            preproven_commitments: preproven_commitments.to_vec(),
            sequencer_commitments_range: (
                *sequencer_commitments_range.start() as u32,
                *sequencer_commitments_range.end() as u32,
            ),
            sequencer_public_key: sequencer_pub_key.clone(),
            sequencer_da_public_key: sequencer_da_pub_key.clone(),
            final_state_root,
            prev_soft_confirmation_hash: initial_soft_confirmation_hash,
            short_header_proofs,
            sequencer_commitments: sequencer_commitments[sequencer_commitments_range.clone()]
                .to_vec(),
            cache_prune_l2_heights,
            last_l1_hash_witness,
        };

        batch_proof_circuit_inputs.push(input);
    }

    Ok((sequencer_commitments, batch_proof_circuit_inputs))
}

pub(crate) async fn prove_l1<Da, Vm, DB>(
    prover_service: Arc<ParallelProverService<Da, Vm>>,
    ledger: DB,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    elfs_by_spec: HashMap<SpecId, Vec<u8>>,
    l1_block: &Da::FilteredBlock,
    sequencer_commitments: Vec<SequencerCommitment>,
    inputs: Vec<BatchProofCircuitInput<'_, Da::Spec, Transaction>>,
) -> anyhow::Result<()>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm,
{
    let l1_height = l1_block.header().height();
    let submitted_proofs = ledger
        .get_proofs_by_l1_height(l1_height)?
        .unwrap_or_default();

    let mut proof_rxs = Vec::with_capacity(inputs.len());
    let inputs_to_prove = inputs
        .into_iter()
        .filter(|input| !state_transition_already_proven::<Da>(input, &submitted_proofs));

    // Add each non-proven proof's data to ProverService
    for input in inputs_to_prove {
        let range_end = input.sequencer_commitments_range.1;

        let last_seq_com = sequencer_commitments
            .get(range_end as usize)
            .expect("Commitment does not exist");
        let last_l2_height = last_seq_com.l2_end_block_number;
        let current_spec = fork_from_block_number(last_l2_height).spec_id;

        let elf = elfs_by_spec
            .get(&current_spec)
            .expect("Every fork should have an elf attached")
            .clone();

        tracing::info!(
            "Proving state transition with ELF of spec: {:?}",
            current_spec
        );

        let input = match current_spec {
            SpecId::Genesis => borsh::to_vec(&BatchProofCircuitInputV1::from(input))?,
            SpecId::Kumquat => borsh::to_vec(&input.into_v2_parts())?,
            _ => borsh::to_vec(&input.into_v3_parts())?,
        };

        let rx = prover_service
            .start_proving(ProofData {
                input,
                assumptions: vec![],
                elf,
            })
            .await;

        proof_rxs.push(rx);
    }

    save_commitments(ledger.clone(), &sequencer_commitments, l1_height);

    tokio::spawn(async move {
        // Wait for all proofs to be completed
        let proofs = futures::future::try_join_all(proof_rxs)
            .await
            .expect("Proving channel should never be closed");

        let txs_and_proofs = prover_service
            .submit_proofs(proofs)
            .await
            .expect("Failed to submit proofs");

        extract_and_store_proof::<DB, Da, Vm>(
            ledger,
            txs_and_proofs,
            code_commitments_by_spec,
            l1_height,
        )
        .await
        .expect("Extract and store proof should not fail");
    });

    Ok(())
}

pub(crate) async fn get_batch_proof_circuit_input_from_commitments<
    'txs,
    Da: DaService,
    DB: BatchProverLedgerOps,
>(
    sequencer_commitments: &[SequencerCommitment],
    da_service: &Arc<Da>,
    ledger_db: &DB,
    l1_block_cache: &Arc<Mutex<L1BlockCache<Da>>>,
    storage_manager: &ProverStorageManager,
    sequencer_k256_pub_key: &[u8],
    sequencer_pub_key: &[u8],
) -> Result<CommitmentStateTransitionData<'txs, Da>, anyhow::Error> {
    let mut committed_l2_blocks = VecDeque::with_capacity(sequencer_commitments.len());
    let mut da_block_headers_of_l2_blocks = VecDeque::with_capacity(sequencer_commitments.len());

    for sequencer_commitment in sequencer_commitments.iter() {
        // get the l2 height ranges of each seq_commitments
        let start_l2 = sequencer_commitment.l2_start_block_number;
        let end_l2 = sequencer_commitment.l2_end_block_number;

        let soft_confirmations_in_commitment = ledger_db
            .get_soft_confirmation_range(
                &(SoftConfirmationNumber(start_l2)..=SoftConfirmationNumber(end_l2)),
            )
            .context("Failed to get soft confirmations")?;
        assert_eq!(
            soft_confirmations_in_commitment
                .last()
                .expect("at least one must exist")
                .l2_height,
            end_l2,
            "Should not try to create circuit input without ensuring the prover is synced"
        );

        let mut l2_blocks = Vec::with_capacity(soft_confirmations_in_commitment.len());
        let mut da_block_headers_to_push: Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader> =
            vec![];
        for soft_confirmation in soft_confirmations_in_commitment {
            if da_block_headers_to_push.is_empty()
                || da_block_headers_to_push.last().unwrap().height()
                    != soft_confirmation.da_slot_height
            {
                let filtered_block = get_da_block_at_height(
                    da_service,
                    soft_confirmation.da_slot_height,
                    l1_block_cache.clone(),
                )
                .await
                .context("Error fetching DA block")?;
                da_block_headers_to_push.push(filtered_block.header().clone());
            }

            let l2_block: L2Block<Transaction> = soft_confirmation
                .try_into()
                .context("Failed to parse transactions")?;

            l2_blocks.push(l2_block);
        }
        committed_l2_blocks.push_back(l2_blocks);

        da_block_headers_of_l2_blocks.push_back(da_block_headers_to_push);
    }

    // Replay transactions in the commitment blocks and collect cumulative witnesses
    let (
        state_transition_witnesses,
        cache_prune_l2_heights,
        short_header_proofs,
        last_l1_hash_witness,
    ) = generate_cumulative_witness(
        &committed_l2_blocks,
        ledger_db,
        da_service,
        l1_block_cache.clone(),
        storage_manager,
        sequencer_k256_pub_key,
        sequencer_pub_key,
    )
    .await?;

    Ok((
        short_header_proofs,
        state_transition_witnesses,
        cache_prune_l2_heights,
        committed_l2_blocks,
        da_block_headers_of_l2_blocks,
        last_l1_hash_witness,
    ))
}

async fn generate_cumulative_witness<'txs, Da: DaService, DB: BatchProverLedgerOps>(
    committed_l2_blocks: &VecDeque<Vec<L2Block<'txs, Transaction>>>,
    ledger_db: &DB,
    da_service: &Arc<Da>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    storage_manager: &ProverStorageManager,
    sequencer_k256_pub_key: &[u8],
    sequencer_pub_key: &[u8],
) -> anyhow::Result<(
    VecDeque<Vec<(Witness, Witness)>>,
    Vec<u64>,
    VecDeque<Vec<u8>>,
    Witness, // last hash witness
)> {
    let mut short_header_proofs: VecDeque<Vec<u8>> = VecDeque::new();

    let mut state_transition_witnesses = VecDeque::with_capacity(committed_l2_blocks.len());

    let mut init_state_root = ledger_db
        .get_l2_state_root(committed_l2_blocks[0][0].l2_height() - 1)?
        .expect("L2 state root must exist");

    let mut cumulative_state_log = None;
    let mut cumulative_offchain_log = None;
    let mut cache_prune_l2_heights = vec![];

    let mut stf =
        StfBlueprint::<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>::new();

    let last_l2_height = committed_l2_blocks
        .back()
        .expect("must have at least one commitment")
        .last()
        .expect("must have at least one l2 block")
        .l2_height();
    // If executed with Fork2 elf, should use cache
    let post_fork2 = fork_from_block_number(last_l2_height).spec_id >= SpecId::Fork2;

    for l2_blocks_in_commitment in committed_l2_blocks {
        let mut witnesses = Vec::with_capacity(l2_blocks_in_commitment.len());

        SHORT_HEADER_PROOF_PROVIDER
            .get()
            .unwrap()
            .clear_queried_hashes();

        for l2_block in l2_blocks_in_commitment {
            let l2_height = l2_block.l2_height();
            let l1_block = get_da_block_at_height(
                da_service,
                l2_block.da_slot_height(),
                l1_block_cache.clone(),
            )
            .await?;

            let pre_state = storage_manager.create_storage_for_l2_height(l2_height);
            let current_spec = fork_from_block_number(l2_height).spec_id;

            let sequencer_public_key = if current_spec >= SpecId::Fork2 {
                sequencer_k256_pub_key
            } else {
                sequencer_pub_key
            };

            let silent_subscriber = tracing_subscriber::registry().with(LevelFilter::OFF);
            let soft_confirmation_result =
                tracing::subscriber::with_default(silent_subscriber, || {
                    stf.apply_soft_confirmation(
                        current_spec,
                        sequencer_public_key,
                        &init_state_root,
                        pre_state,
                        cumulative_state_log.take(),
                        cumulative_offchain_log.take(),
                        Default::default(),
                        Default::default(),
                        l1_block.header(),
                        l2_block,
                    )
                })?;

            assert_eq!(
                l2_block.state_root(),
                soft_confirmation_result.state_root_transition.final_root,
                "State root mismatch when regenerating witnesses"
            );

            init_state_root = soft_confirmation_result.state_root_transition.final_root;

            if post_fork2 {
                let mut state_log = soft_confirmation_result.state_log;
                let mut offchain_log = soft_confirmation_result.offchain_log;

                // If cache grew too large, zkvm will error with OOM, hence, we pass
                // when to prune as hint
                if state_log.estimated_cache_size() + offchain_log.estimated_cache_size()
                    > MAX_CUMULATIVE_CACHE_SIZE
                {
                    state_log.prune_half();
                    offchain_log.prune_half();
                    cache_prune_l2_heights.push(l2_height);
                }

                cumulative_state_log = Some(state_log);
                cumulative_offchain_log = Some(offchain_log);
            }

            witnesses.push((
                soft_confirmation_result.witness,
                soft_confirmation_result.offchain_witness,
            ));
        }

        let new_hashes = SHORT_HEADER_PROOF_PROVIDER
            .get()
            .unwrap()
            .take_queried_hashes(
                l2_blocks_in_commitment[0].l2_height()
                    ..=l2_blocks_in_commitment
                        .last()
                        .expect("must have at least one")
                        .l2_height(),
            );

        for hash in new_hashes {
            let serialized_shp = ledger_db
                .get_short_header_proof_by_l1_hash(&hash)?
                .expect("Should exist");

            short_header_proofs.push_back(serialized_shp);
        }

        state_transition_witnesses.push_back(witnesses);
    }

    let mut last_l1_hash_witness = Witness::default();
    // if post fork2 we always need to read the last L1 hash on Bitcoin Light Client contract
    // if the provider have some hashes, circuit will use that.
    if post_fork2 && short_header_proofs.is_empty() {
        let cumulative_state_log = cumulative_state_log.unwrap();
        let prover_storage = storage_manager.create_storage_for_l2_height(last_l2_height + 1);

        // we don't care about the return here
        // we only care about the last hash witness getting filled (or not)
        let _ = citrea_stf::verifier::get_last_l1_hash_on_contract::<DefaultContext>(
            cumulative_state_log,
            prover_storage,
            &mut last_l1_hash_witness,
            [0u8; 32], // final state root is only needed for JMT proof verification
        );
    }

    Ok((
        state_transition_witnesses,
        cache_prune_l2_heights,
        short_header_proofs,
        last_l1_hash_witness,
    ))
}

/// TODO: This check needs a rewrite for sure.
/// We could check on the sequencer commitments range only and not generate inputs
pub(crate) fn state_transition_already_proven<Da: DaService>(
    input: &BatchProofCircuitInput<Da::Spec, Transaction>,
    proofs: &Vec<StoredBatchProof>,
) -> bool {
    for proof in proofs {
        let (initial_state_root, sequencer_commitments_range) = match &proof.proof_output {
            StoredBatchProofOutput::V1(output) => (
                output.initial_state_root,
                output.sequencer_commitments_range,
            ),
            StoredBatchProofOutput::V2(output) => (
                output.initial_state_root,
                output.sequencer_commitments_range,
            ),
            StoredBatchProofOutput::V3(output) => (
                output.initial_state_root,
                (u32::MAX, u32::MAX), // TODO: find another way for v3
            ),
        };

        if initial_state_root == input.initial_state_root.as_ref()
            && sequencer_commitments_range == input.sequencer_commitments_range
        {
            return true;
        }
    }
    false
}

pub(crate) async fn extract_and_store_proof<DB, Da, Vm>(
    ledger_db: DB,
    txs_and_proofs: Vec<(<Da as DaService>::TransactionId, Proof)>,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    l1_height: u64,
) -> Result<(), anyhow::Error>
where
    Da: DaService,
    DB: BatchProverLedgerOps,
    Vm: ZkvmHost + Zkvm,
{
    for (tx_id, proof) in txs_and_proofs {
        let tx_id_u8 = tx_id.into();

        // l1_height => (tx_id, proof, circuit_output)
        // save proof along with tx id to db, should be queryable by slot number or slot hash
        let (last_active_spec_id, batch_proof_output) = match Vm::extract_output::<
            BatchProofCircuitOutputV3,
        >(&proof)
        {
            Ok(output) => (SpecId::Fork2, StoredBatchProofOutput::V3(output)),
            Err(e) => {
                info!("Failed to extract post fork 2 output from proof: {:?}. Trying to extract pre fork 2 output", e);
                match Vm::extract_output::<BatchProofCircuitOutputV2>(&proof) {
                    Ok(output) => (SpecId::Kumquat, StoredBatchProofOutput::V2(output)),
                    Err(e) => {
                        info!("Failed to extract kumquat fork output from proof: {:?}. Trying to extract genesis fork output", e);
                        let output = Vm::extract_output::<BatchProofCircuitOutputV1>(&proof)
                            .expect("Should be able to extract either pre or post fork 1 output");

                        // If we got output of pre fork 1 that means we are in genesis
                        (SpecId::Genesis, StoredBatchProofOutput::V1(output))
                    }
                }
            }
        };

        let code_commitment = code_commitments_by_spec
            .get(&last_active_spec_id)
            .expect("Proof public input must contain valid spec id");

        info!("Verifying proof with image ID: {:?}", code_commitment);

        Vm::verify(proof.as_slice(), code_commitment)
            .map_err(|err| anyhow!("Failed to verify proof: {:?}. Skipping it...", err))?;

        debug!("circuit output: {:?}", batch_proof_output);

        if let Err(e) = ledger_db.insert_batch_proof_data_by_l1_height(
            l1_height,
            tx_id_u8,
            proof,
            batch_proof_output,
        ) {
            panic!("Failed to put proof data in the ledger db: {}", e);
        }
    }
    Ok(())
}

pub(crate) fn save_commitments<DB>(
    ledger_db: DB,
    sequencer_commitments: &[SequencerCommitment],
    l1_height: u64,
) where
    DB: BatchProverLedgerOps,
{
    for sequencer_commitment in sequencer_commitments.iter() {
        // Save commitments on prover ledger db
        ledger_db
            .update_commitments_on_da_slot(l1_height, sequencer_commitment.clone())
            .unwrap();

        let l2_start_height = sequencer_commitment.l2_start_block_number;
        let l2_end_height = sequencer_commitment.l2_end_block_number;
        for i in l2_start_height..=l2_end_height {
            ledger_db
                .put_l2_block_status(SoftConfirmationNumber(i), SoftConfirmationStatus::Proven)
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to put soft confirmation status in the ledger db {}",
                        i
                    )
                });
        }
    }
}
