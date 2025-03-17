use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use citrea_common::da::extract_sequencer_commitments;
use citrea_common::utils::check_l2_block_exists;
use citrea_primitives::forks::{fork_from_block_number, get_fork2_activation_height_non_zero};
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use prover_services::{ParallelProverService, ProofData};
use serde::{Deserialize, Serialize};
use short_header_proof_provider::SHORT_HEADER_PROOF_PROVIDER;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::batch_proof::{StoredBatchProof, StoredBatchProofOutput};
use sov_db::schema::types::L2BlockNumber;
use sov_keys::default_signature::K256PublicKey;
use sov_modules_api::{L2Block, SlotData, SpecId, Zkvm};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::{BlockHeaderTrait, SequencerCommitment};
use sov_rollup_interface::rpc::L2BlockStatus;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::batch_proof::input::v3::BatchProofCircuitInputV3;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;
use sov_rollup_interface::zk::{Proof, ReceiptType, ZkvmHost};
use sov_state::Witness;
use tracing::level_filters::LevelFilter;
use tracing::{debug, info};
use tracing_subscriber::layer::SubscriberExt;

use crate::da_block_handler::break_sequencer_commitments_into_groups;
use crate::errors::L1ProcessingError;

const MAX_CUMULATIVE_CACHE_SIZE: usize = 128 * 1024 * 1024;

type CommitmentStateTransitionData = (
    VecDeque<Vec<u8>>,
    VecDeque<Vec<(Witness, Witness)>>,
    Vec<u64>,
    VecDeque<Vec<L2Block>>,
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
pub(crate) async fn data_to_prove<Da, DB>(
    da_service: Arc<Da>,
    ledger: DB,
    storage_manager: &ProverStorageManager,
    sequencer_pub_key: K256PublicKey,
    sequencer_da_pub_key: Vec<u8>,
    l1_block: &<Da as DaService>::FilteredBlock,
    group_commitments: Option<GroupCommitments>,
) -> Result<
    (
        Vec<SequencerCommitment>,
        // (u32, u32) represents the range of commitments (as found in da and sorted)
        // which can be removed once we put indices inside sequencer commitments directly
        Vec<(BatchProofCircuitInputV3, (u32, u32))>,
    ),
    L1ProcessingError,
>
where
    Da: DaService,
    DB: BatchProverLedgerOps,
{
    let l1_height = l1_block.header().height();

    let mut sequencer_commitments: Vec<SequencerCommitment> =
        extract_sequencer_commitments::<Da>(da_service.clone(), l1_block, &sequencer_da_pub_key);

    if sequencer_commitments.is_empty() {
        return Err(L1ProcessingError::NoSeqCommitments {
            l1_height: l1_block.header().height(),
        });
    }
    // TODO: Make sure commitment indexes are sequential

    // Store commitments by index
    for commitment in sequencer_commitments.iter() {
        ledger
            .put_commitment_by_index(commitment)
            .expect("Should store commitment");
    }

    let l2_start_block_number = if sequencer_commitments[0].index == 0 {
        // If this is the first commitment in fork2, the start l2 height will be fork2 activation height
        // Start block number should be fork2  activation height
        get_fork2_activation_height_non_zero()
    } else {
        let previous_commitment_index = sequencer_commitments[0].index - 1;
        // If this is not the first commitment in fork2, the start l2 height will be the end block number of the previous commitment
        ledger
            .get_commitment_by_index(previous_commitment_index)
            .expect("Ledger should not error out")
            .expect("There should exist a commitment")
            .l2_end_block_number
            + 1
    };

    // If the L2 range does not exist, we break off the local loop getting back to
    // the outer loop / select to make room for other tasks to run.
    // We retry the L1 block there as well.
    let start_block_number = l2_start_block_number;
    let end_block_number =
        sequencer_commitments[sequencer_commitments.len() - 1].l2_end_block_number;

    // Verify that we have all l2 blocks synced to execute the commitment
    if !check_l2_block_exists(&ledger, end_block_number) {
        return Err(L1ProcessingError::L2RangeMissing {
            start_block_number,
            end_block_number,
        });
    }

    sequencer_commitments.sort();

    if sequencer_commitments.is_empty() {
        return Err(L1ProcessingError::DuplicateCommitments { l1_height });
    }

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

    for (idx, sequencer_commitments_range) in ranges.iter().enumerate() {
        let first_l2_height_of_l1 = if idx == 0 {
            // If at first commitment the start height should be the start block number
            // Which is end height + 1 of the previous commitment
            start_block_number
        } else {
            // If not at first commitment the start height should be the end height + 1 of the previous commitment in the commitments array
            sequencer_commitments[*ranges[idx - 1].end()].l2_end_block_number + 1
        };

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
            last_l1_hash_witness,
        ) = get_batch_proof_circuit_input_from_commitments::<Da, _>(
            first_l2_height_of_l1,
            &sequencer_commitments[sequencer_commitments_range.clone()],
            &ledger,
            storage_manager,
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

        let previous_sequencer_commitment = sequencer_commitments
            [*sequencer_commitments_range.start()]
        .index
        .checked_sub(1)
        .map(|index| {
            ledger
                .get_commitment_by_index(index)
                .expect("Should get commitment")
                .expect("Commitment should exist")
        });

        let input = BatchProofCircuitInputV3 {
            initial_state_root,
            final_state_root,
            l2_blocks,
            state_transition_witnesses,
            short_header_proofs,
            sequencer_commitments: sequencer_commitments[sequencer_commitments_range.clone()]
                .to_vec(),
            cache_prune_l2_heights,
            last_l1_hash_witness,
            previous_sequencer_commitment,
        };

        batch_proof_circuit_inputs.push((
            input,
            (
                *sequencer_commitments_range.start() as u32,
                *sequencer_commitments_range.end() as u32,
            ),
        ));
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
    inputs: Vec<(BatchProofCircuitInputV3, (u32, u32))>,
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
        .filter(|input| !state_transition_already_proven(input, &submitted_proofs));

    // Add each non-proven proof's data to ProverService
    for (input, sequencer_commitment_range) in inputs_to_prove {
        let range_end = sequencer_commitment_range.1;

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

        let input = borsh::to_vec(&input.into_v3_parts())?;

        let rx = prover_service
            .start_proving(
                ProofData {
                    input,
                    assumptions: vec![],
                    elf,
                },
                ReceiptType::Groth16,
            )
            .await;

        proof_rxs.push(rx);
    }

    save_commitments(ledger.clone(), &sequencer_commitments, l1_height);

    tokio::spawn(async move {
        // Wait for all proofs to be completed
        while !proof_rxs.is_empty() {
            let (proof, _, remaining_rxs) = futures::future::select_all(proof_rxs).await;

            proof_rxs = remaining_rxs;
            let proof = proof.expect("Proof channel should never close");

            match prover_service.submit_proof(proof.clone()).await {
                Ok(tx_id) => {
                    extract_and_store_proof::<_, Da, Vm>(
                        &ledger,
                        tx_id,
                        proof,
                        &code_commitments_by_spec,
                        l1_height,
                    )
                    .await
                    .expect("Extract and store proof should not fail");
                }
                Err(e) => {
                    tracing::error!("Failed to submit proof to DA: {e}");
                    continue;
                }
            }
        }
    });

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn get_batch_proof_circuit_input_from_commitments<
    Da: DaService,
    DB: BatchProverLedgerOps,
>(
    first_l2_height_of_commitments: u64,
    sequencer_commitments: &[SequencerCommitment],
    ledger_db: &DB,
    storage_manager: &ProverStorageManager,
    sequencer_pub_key: &K256PublicKey,
) -> Result<CommitmentStateTransitionData, anyhow::Error> {
    let mut committed_l2_blocks = VecDeque::with_capacity(sequencer_commitments.len());

    for (idx, sequencer_commitment) in sequencer_commitments.iter().enumerate() {
        // get the l2 height ranges of each seq_commitments

        let start_l2 = if idx == 0 {
            first_l2_height_of_commitments
        } else {
            sequencer_commitments[idx - 1].l2_end_block_number + 1
        };
        let end_l2 = sequencer_commitment.l2_end_block_number;

        let l2_blocks_in_commitment = ledger_db
            .get_l2_block_range(&(L2BlockNumber(start_l2)..=L2BlockNumber(end_l2)))
            .context("Failed to get l2 blocks")?;
        assert_eq!(
            l2_blocks_in_commitment
                .last()
                .expect("at least one must exist")
                .height,
            end_l2,
            "Should not try to create circuit input without ensuring the prover is synced"
        );

        let mut l2_blocks = Vec::with_capacity(l2_blocks_in_commitment.len());

        for l2_block in l2_blocks_in_commitment {
            let l2_block: L2Block = l2_block
                .try_into()
                .context("Failed to parse transactions")?;

            l2_blocks.push(l2_block);
        }
        committed_l2_blocks.push_back(l2_blocks);
    }

    // Replay transactions in the commitment blocks and collect cumulative witnesses
    let (
        state_transition_witnesses,
        cache_prune_l2_heights,
        short_header_proofs,
        last_l1_hash_witness,
    ) = generate_cumulative_witness::<Da, _>(
        &committed_l2_blocks,
        ledger_db,
        storage_manager,
        sequencer_pub_key,
    )
    .await?;

    Ok((
        short_header_proofs,
        state_transition_witnesses,
        cache_prune_l2_heights,
        committed_l2_blocks,
        last_l1_hash_witness,
    ))
}

async fn generate_cumulative_witness<Da: DaService, DB: BatchProverLedgerOps>(
    committed_l2_blocks: &VecDeque<Vec<L2Block>>,
    ledger_db: &DB,
    storage_manager: &ProverStorageManager,
    sequencer_pub_key: &K256PublicKey,
) -> anyhow::Result<(
    VecDeque<Vec<(Witness, Witness)>>,
    Vec<u64>,
    VecDeque<Vec<u8>>,
    Witness, // last hash witness
)> {
    let mut short_header_proofs: VecDeque<Vec<u8>> = VecDeque::new();

    let mut state_transition_witnesses = VecDeque::with_capacity(committed_l2_blocks.len());

    let mut init_state_root = ledger_db
        .get_l2_state_root(committed_l2_blocks[0][0].height() - 1)?
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
        .height();

    for l2_blocks_in_commitment in committed_l2_blocks {
        let mut witnesses = Vec::with_capacity(l2_blocks_in_commitment.len());

        SHORT_HEADER_PROOF_PROVIDER
            .get()
            .unwrap()
            .clear_queried_hashes();

        for l2_block in l2_blocks_in_commitment {
            let l2_height = l2_block.height();

            let pre_state = storage_manager.create_storage_for_l2_height(l2_height);
            let current_spec = fork_from_block_number(l2_height).spec_id;

            let silent_subscriber = tracing_subscriber::registry().with(LevelFilter::OFF);
            let l2_block_result = tracing::subscriber::with_default(silent_subscriber, || {
                stf.apply_l2_block(
                    current_spec,
                    sequencer_pub_key,
                    &init_state_root,
                    pre_state,
                    cumulative_state_log.take(),
                    cumulative_offchain_log.take(),
                    Default::default(),
                    Default::default(),
                    l2_block,
                )
            })?;

            assert_eq!(
                l2_block.state_root(),
                l2_block_result.state_root_transition.final_root,
                "State root mismatch when regenerating witnesses"
            );

            init_state_root = l2_block_result.state_root_transition.final_root;

            let mut state_log = l2_block_result.state_log;
            let mut offchain_log = l2_block_result.offchain_log;

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

            witnesses.push((l2_block_result.witness, l2_block_result.offchain_witness));
        }

        let new_hashes = SHORT_HEADER_PROOF_PROVIDER
            .get()
            .unwrap()
            .take_queried_hashes(
                l2_blocks_in_commitment[0].height()
                    ..=l2_blocks_in_commitment
                        .last()
                        .expect("must have at least one")
                        .height(),
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
    if short_header_proofs.is_empty() {
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
pub(crate) fn state_transition_already_proven(
    input: &(BatchProofCircuitInputV3, (u32, u32)),
    proofs: &Vec<StoredBatchProof>,
) -> bool {
    for proof in proofs {
        let (initial_state_root, sequencer_commitments_range) = match &proof.proof_output {
            StoredBatchProofOutput::V3(output) => (
                output.initial_state_root,
                (u32::MAX, u32::MAX), // TODO: find another way for v3 <= this can be handled pretty easily once we merge #2014
            ),
        };

        if initial_state_root == input.0.initial_state_root.as_ref()
            && sequencer_commitments_range == input.1
        {
            return true;
        }
    }
    false
}

pub(crate) async fn extract_and_store_proof<DB, Da, Vm>(
    ledger_db: &DB,
    tx_id: <Da as DaService>::TransactionId,
    proof: Proof,
    code_commitments_by_spec: &HashMap<SpecId, Vm::CodeCommitment>,
    l1_height: u64,
) -> Result<(), anyhow::Error>
where
    Da: DaService,
    DB: BatchProverLedgerOps,
    Vm: ZkvmHost + Zkvm,
{
    let tx_id_u8 = tx_id.into();

    // l1_height => (tx_id, proof, circuit_output)
    // save proof along with tx id to db, should be queryable by slot number or slot hash
    let batch_proof_output = Vm::extract_output::<BatchProofCircuitOutput>(&proof)
        .map_err(|e| anyhow!("Failed to extract batch proof output from proof: {:?}", e))?;

    let last_active_spec_id = SpecId::Fork2;

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
        batch_proof_output.into(),
    ) {
        panic!("Failed to put proof data in the ledger db: {}", e);
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
        let l2_start_block_number = if sequencer_commitment.index == 0 {
            get_fork2_activation_height_non_zero()
        } else {
            ledger_db
                .get_commitment_by_index(sequencer_commitment.index - 1)
                .expect("Ledger should not error out")
                .expect("There should exist a commitment")
                .l2_end_block_number
                + 1
        };
        // Save commitments on prover ledger db
        ledger_db
            .update_commitments_on_da_slot(l1_height, sequencer_commitment.clone())
            .unwrap();

        let l2_start_height = l2_start_block_number;
        let l2_end_height = sequencer_commitment.l2_end_block_number;
        for i in l2_start_height..=l2_end_height {
            ledger_db
                .put_l2_block_status(L2BlockNumber(i), L2BlockStatus::Proven)
                .unwrap_or_else(|_| panic!("Failed to put l2 block status in the ledger db {}", i));
        }
    }
}
