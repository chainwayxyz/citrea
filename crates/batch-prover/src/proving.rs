use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::anyhow;
use borsh::{BorshDeserialize, BorshSerialize};
use citrea_common::cache::L1BlockCache;
use citrea_common::da::extract_sequencer_commitments;
use citrea_common::utils::{check_l2_block_exists, filter_out_proven_commitments};
use citrea_primitives::forks::fork_from_block_number;
use prover_services::{ParallelProverService, ProofData};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::{SoftConfirmationNumber, StoredBatchProof, StoredBatchProofOutput};
use sov_modules_api::{SlotData, SpecId, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, DaNamespace, DaSpec, SequencerCommitment};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::batch_proof::input::v1::BatchProofCircuitInputV1;
use sov_rollup_interface::zk::batch_proof::input::BatchProofCircuitInput;
use sov_rollup_interface::zk::batch_proof::output::v1::BatchProofCircuitOutputV1;
use sov_rollup_interface::zk::batch_proof::output::v2::BatchProofCircuitOutputV2;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::da_block_handler::{
    break_sequencer_commitments_into_groups, get_batch_proof_circuit_input_from_commitments,
};
use crate::errors::L1ProcessingError;

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

pub(crate) async fn data_to_prove<'txs, Da, DB, Witness, Tx>(
    da_service: Arc<Da>,
    ledger: DB,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    l1_block: &<Da as DaService>::FilteredBlock,
    group_commitments: Option<GroupCommitments>,
) -> Result<
    (
        Vec<SequencerCommitment>,
        Vec<BatchProofCircuitInput<'txs, Witness, Da::Spec, Tx>>,
    ),
    L1ProcessingError,
>
where
    Da: DaService,
    DB: BatchProverLedgerOps,
    Witness: DeserializeOwned,
    Tx: Clone + BorshDeserialize + 'txs,
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

    let (sequencer_commitments, preproven_commitments) =
        filter_out_proven_commitments(&ledger, &sequencer_commitments).map_err(|e| {
            L1ProcessingError::Other(format!("Error filtering out proven commitments: {}", e))
        })?;

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
            state_transition_witnesses,
            soft_confirmations,
            da_block_headers_of_soft_confirmations,
        ) = get_batch_proof_circuit_input_from_commitments(
            &sequencer_commitments[sequencer_commitments_range.clone()],
            &da_service,
            &ledger,
            &l1_block_cache,
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

        let input: BatchProofCircuitInput<Witness, Da::Spec, Tx> = BatchProofCircuitInput {
            initial_state_root,
            da_data: da_data.clone(),
            da_block_header_of_commitments: da_block_header_of_commitments.clone(),
            inclusion_proof: inclusion_proof.clone(),
            completeness_proof: completeness_proof.clone(),
            soft_confirmations,
            state_transition_witnesses,
            da_block_headers_of_soft_confirmations,
            preproven_commitments: preproven_commitments.to_vec(),
            sequencer_commitments_range: (
                *sequencer_commitments_range.start() as u32,
                *sequencer_commitments_range.end() as u32,
            ),
            sequencer_public_key: sequencer_pub_key.clone(),
            sequencer_da_public_key: sequencer_da_pub_key.clone(),
            final_state_root,
            prev_soft_confirmation_hash: initial_soft_confirmation_hash,
        };

        batch_proof_circuit_inputs.push(input);
    }

    Ok((sequencer_commitments, batch_proof_circuit_inputs))
}

pub(crate) async fn prove_l1<Da, Vm, DB, Witness, Tx>(
    prover_service: Arc<ParallelProverService<Da, Vm>>,
    ledger: DB,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    elfs_by_spec: HashMap<SpecId, Vec<u8>>,
    l1_block: &Da::FilteredBlock,
    sequencer_commitments: Vec<SequencerCommitment>,
    inputs: Vec<BatchProofCircuitInput<'_, Witness, Da::Spec, Tx>>,
) -> anyhow::Result<()>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm,
    Witness: Default + BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned,
    Tx: Clone + BorshSerialize,
{
    let submitted_proofs = ledger
        .get_proofs_by_l1_height(l1_block.header().height())?
        .unwrap_or(vec![]);

    // Add each non-proven proof's data to ProverService
    for input in inputs {
        if !state_transition_already_proven::<Witness, Da, Tx>(&input, &submitted_proofs) {
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
                // TODO: activate this once we freeze Kumquat ELFs
                // SpecId::Kumquat => borsh::to_vec(&input.into_v2_parts())?,
                _ => borsh::to_vec(&input.into_v3_parts())?,
            };

            prover_service
                .add_proof_data(ProofData {
                    input,
                    assumptions: vec![],
                    elf,
                    is_post_genesis_batch: current_spec > SpecId::Genesis,
                })
                .await;
        }
    }

    // Prove all proofs in parallel
    let proofs = prover_service.prove().await?;

    let txs_and_proofs = prover_service.submit_proofs(proofs).await?;

    extract_and_store_proof::<DB, Da, Vm>(
        ledger.clone(),
        txs_and_proofs,
        code_commitments_by_spec.clone(),
    )
    .await?;

    save_commitments(
        ledger.clone(),
        &sequencer_commitments,
        l1_block.header().height(),
    );

    Ok(())
}

pub(crate) fn state_transition_already_proven<Witness, Da, Tx>(
    input: &BatchProofCircuitInput<Witness, Da::Spec, Tx>,
    proofs: &Vec<StoredBatchProof>,
) -> bool
where
    Da: DaService,
    Witness: Default + BorshDeserialize + Serialize + DeserializeOwned,
    Tx: Clone,
{
    for proof in proofs {
        if proof.proof_output.initial_state_root == input.initial_state_root.as_ref()
            && proof.proof_output.sequencer_commitments_range == input.sequencer_commitments_range
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
        let (last_active_spec_id, circuit_output) = match Vm::extract_output::<
            BatchProofCircuitOutputV2<<Da as DaService>::Spec>,
        >(&proof)
        {
            Ok(output) => (
                fork_from_block_number(output.last_l2_height).spec_id,
                output,
            ),
            Err(e) => {
                info!("Failed to extract post fork 1 output from proof: {:?}. Trying to extract pre fork 1 output", e);
                let output = Vm::extract_output::<BatchProofCircuitOutputV1<Da::Spec>>(&proof)
                    .expect("Should be able to extract either pre or post fork 1 output");
                let batch_proof_output = BatchProofCircuitOutputV2::<Da::Spec> {
                    initial_state_root: output.initial_state_root,
                    final_state_root: output.final_state_root,
                    state_diff: output.state_diff,
                    da_slot_hash: output.da_slot_hash,
                    sequencer_commitments_range: output.sequencer_commitments_range,
                    sequencer_public_key: output.sequencer_public_key,
                    sequencer_da_public_key: output.sequencer_da_public_key,
                    preproven_commitments: output.preproven_commitments,
                    // We don't have these fields in pre fork 1
                    // That's why we serve them as 0
                    prev_soft_confirmation_hash: [0; 32],
                    final_soft_confirmation_hash: [0; 32],
                    last_l2_height: 0,
                };
                // If we got output of pre fork 1 that means we are in genesis
                (SpecId::Genesis, batch_proof_output)
            }
        };

        let code_commitment = code_commitments_by_spec
            .get(&last_active_spec_id)
            .expect("Proof public input must contain valid spec id");

        info!("Verifying proof with image ID: {:?}", code_commitment);

        Vm::verify(proof.as_slice(), code_commitment)
            .map_err(|err| anyhow!("Failed to verify proof: {:?}. Skipping it...", err))?;

        debug!("circuit output: {:?}", circuit_output);

        let slot_hash = circuit_output.da_slot_hash.into();

        let stored_batch_proof_output = StoredBatchProofOutput {
            initial_state_root: circuit_output.initial_state_root.as_ref().to_vec(),
            final_state_root: circuit_output.final_state_root.as_ref().to_vec(),
            state_diff: circuit_output.state_diff,
            da_slot_hash: slot_hash,
            sequencer_commitments_range: circuit_output.sequencer_commitments_range,
            sequencer_public_key: circuit_output.sequencer_public_key,
            sequencer_da_public_key: circuit_output.sequencer_da_public_key,
            preproven_commitments: circuit_output.preproven_commitments,
            prev_soft_confirmation_hash: circuit_output.prev_soft_confirmation_hash,
            final_soft_confirmation_hash: circuit_output.final_soft_confirmation_hash,
            last_l2_height: circuit_output.last_l2_height,
        };
        let l1_height = ledger_db
            .get_l1_height_of_l1_hash(slot_hash)?
            .expect("l1 height should exist");

        if let Err(e) = ledger_db.insert_batch_proof_data_by_l1_height(
            l1_height,
            tx_id_u8,
            proof,
            stored_batch_proof_output,
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
                .put_soft_confirmation_status(
                    SoftConfirmationNumber(i),
                    SoftConfirmationStatus::Proven,
                )
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to put soft confirmation status in the ledger db {}",
                        i
                    )
                });
        }
    }
}
