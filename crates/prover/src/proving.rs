use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::anyhow;
use borsh::{BorshDeserialize, BorshSerialize};
use citrea_common::cache::L1BlockCache;
use citrea_common::da::extract_sequencer_commitments;
use citrea_common::utils::{check_l2_range_exists, filter_out_proven_commitments};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_db::ledger_db::ProverLedgerOps;
use sov_db::schema::types::{BatchNumber, StoredProof, StoredStateTransition};
use sov_modules_api::{BlobReaderTrait, SlotData, SpecId, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec, SequencerCommitment};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::{Proof, StateTransitionData, ZkvmHost};
use sov_stf_runner::ProverService;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::da_block_handler::{
    break_sequencer_commitments_into_groups, get_state_transition_data_from_commitments,
};
use crate::errors::L1ProcessingError;

type TxId<Da> = <Da as DaService>::TransactionId;

pub(crate) async fn data_to_prove<Da, DB, StateRoot, Witness>(
    da_service: Arc<Da>,
    ledger: DB,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    l1_block: <Da as DaService>::FilteredBlock,
    group_commitments: Option<bool>,
) -> Result<
    (
        Vec<SequencerCommitment>,
        Vec<StateTransitionData<StateRoot, Witness, Da::Spec>>,
    ),
    L1ProcessingError,
>
where
    Da: DaService,
    DB: ProverLedgerOps + Clone + Send + Sync + 'static,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
    Witness: Default + BorshDeserialize + Serialize + DeserializeOwned,
{
    let l1_height = l1_block.header().height();

    let mut da_data: Vec<<<Da as DaService>::Spec as DaSpec>::BlobTransaction> =
        da_service.extract_relevant_blobs(&l1_block);

    // if we don't do this, the zk circuit can't read the sequencer commitments
    da_data.iter_mut().for_each(|blob| {
        blob.full_data();
    });

    let sequencer_commitments: Vec<SequencerCommitment> = extract_sequencer_commitments::<Da>(
        da_service.clone(),
        l1_block.clone(),
        &sequencer_da_pub_key,
    );

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

    // If range is not synced yet return error
    if !check_l2_range_exists(&ledger, start_block_number, end_block_number) {
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
        Some(true) => break_sequencer_commitments_into_groups(&ledger, &sequencer_commitments)
            .map_err(|e| {
                L1ProcessingError::Other(format!(
                    "Error breaking sequencer commitments into groups: {:?}",
                    e
                ))
            })?,
        _ => vec![(0..=sequencer_commitments.len() - 1)],
    };

    let mut state_transitions = vec![];

    for sequencer_commitments_range in ranges {
        let first_l2_height_of_l1 =
            sequencer_commitments[*sequencer_commitments_range.start()].l2_start_block_number;
        let last_l2_height_of_l1 =
            sequencer_commitments[*sequencer_commitments_range.end()].l2_end_block_number;
        let (
            state_transition_witnesses,
            soft_confirmations,
            da_block_headers_of_soft_confirmations,
        ) = get_state_transition_data_from_commitments(
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
            .get_l2_state_root::<StateRoot>(first_l2_height_of_l1 - 1)
            .map_err(|e| {
                L1ProcessingError::Other(format!("Error getting initial state root: {:?}", e))
            })?
            .expect("There should be a state root");
        let initial_batch_hash = ledger
            .get_soft_confirmation_by_number(&BatchNumber(first_l2_height_of_l1))
            .map_err(|e| {
                L1ProcessingError::Other(format!("Error getting initial batch hash: {:?}", e))
            })?
            .ok_or(L1ProcessingError::Other(format!(
                "Could not find soft batch at height {}",
                first_l2_height_of_l1
            )))?
            .prev_hash;

        let final_state_root = ledger
            .get_l2_state_root::<StateRoot>(last_l2_height_of_l1)
            .map_err(|e| {
                L1ProcessingError::Other(format!("Error getting final state root: {:?}", e))
            })?
            .expect("There should be a state root");

        let (inclusion_proof, completeness_proof) =
            da_service.get_extraction_proof(&l1_block, &da_data).await;

        let state_transition_data: StateTransitionData<StateRoot, Witness, Da::Spec> =
            StateTransitionData {
                initial_state_root,
                final_state_root,
                initial_batch_hash,
                da_data: da_data.clone(),
                da_block_header_of_commitments: da_block_header_of_commitments.clone(),
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
                sequencer_public_key: sequencer_pub_key.clone(),
                sequencer_da_public_key: sequencer_da_pub_key.clone(),
            };

        state_transitions.push(state_transition_data);
    }

    Ok((sequencer_commitments, state_transitions))
}

pub(crate) async fn prove_l1<Da, Ps, Vm, DB, StateRoot, Witness>(
    da_service: Arc<Da>,
    prover_service: Arc<Ps>,
    ledger: DB,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    l1_block: Da::FilteredBlock,
    sequencer_commitments: Vec<SequencerCommitment>,
    state_transitions: Vec<StateTransitionData<StateRoot, Witness, Da::Spec>>,
) -> anyhow::Result<()>
where
    Da: DaService,
    DB: ProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<Vm, DaService = Da, StateRoot = StateRoot, Witness = Witness>,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
    Witness: Default + BorshDeserialize + Serialize + DeserializeOwned,
{
    let submitted_proofs = ledger
        .get_proofs_by_l1_height(l1_block.header().height())
        .map_err(|e| anyhow!("{e}"))?
        .unwrap_or(vec![]);

    let da_block_hash = l1_block.header().hash();

    for state_transition_data in state_transitions {
        if !state_transition_already_proven::<StateRoot, Witness, Da>(
            &state_transition_data,
            &submitted_proofs,
        ) {
            let (tx_id, proof) = generate_and_submit_proof(
                prover_service.clone(),
                da_service.clone(),
                state_transition_data,
                da_block_hash.clone(),
            )
            .await
            .map_err(|e| anyhow!("{e}"))?;

            extract_and_store_proof::<DB, Da, Vm, StateRoot>(
                ledger.clone(),
                tx_id,
                proof,
                code_commitments_by_spec.clone(),
            )
            .await
            .map_err(|e| anyhow!("{e}"))?;

            save_commitments(
                ledger.clone(),
                &sequencer_commitments,
                l1_block.header().height(),
            );
        }
    }

    Ok(())
}

pub(crate) async fn generate_and_submit_proof<Ps, Vm, Da, StateRoot, Witness>(
    prover_service: Arc<Ps>,
    da_service: Arc<Da>,
    transition_data: StateTransitionData<StateRoot, Witness, Da::Spec>,
    hash: <<Da as DaService>::Spec as DaSpec>::SlotHash,
) -> Result<(TxId<Da>, Proof), anyhow::Error>
where
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<Vm, DaService = Da, StateRoot = StateRoot, Witness = Witness>,
    Da: DaService,
{
    tracing::error!(
        "Submitting for proving. L1 height: {}\tL2 blocks: #{}-#{}",
        transition_data.da_block_header_of_commitments.height(),
        transition_data.soft_confirmations[0][0].l2_height(),
        transition_data
            .soft_confirmations
            .iter()
            .last()
            .unwrap()
            .iter()
            .last()
            .unwrap()
            .l2_height()
    );

    prover_service.submit_witness(transition_data).await;

    prover_service.prove(hash.clone()).await?;

    prover_service
        .wait_for_proving_and_send_to_da(hash.clone(), &da_service)
        .await
        .map_err(|e| anyhow!("Failed to prove and send to DA: {}", e))
}

pub(crate) fn state_transition_already_proven<StateRoot, Witness, Da>(
    state_transition: &StateTransitionData<StateRoot, Witness, Da::Spec>,
    proofs: &Vec<StoredProof>,
) -> bool
where
    Da: DaService,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
    Witness: Default + BorshDeserialize + Serialize + DeserializeOwned,
{
    for proof in proofs {
        if proof.state_transition.initial_state_root == state_transition.initial_state_root.as_ref()
            && proof.state_transition.final_state_root == state_transition.final_state_root.as_ref()
            && proof.state_transition.sequencer_commitments_range
                == state_transition.sequencer_commitments_range
        {
            return true;
        }
    }
    false
}

pub(crate) async fn extract_and_store_proof<DB, Da, Vm, StateRoot>(
    ledger_db: DB,
    tx_id: <Da as DaService>::TransactionId,
    proof: Proof,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
) -> Result<(), anyhow::Error>
where
    Da: DaService,
    DB: ProverLedgerOps,
    Vm: ZkvmHost + Zkvm,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
{
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
            let code_commitment = code_commitments_by_spec
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
    let l1_height = ledger_db
        .get_l1_height_of_l1_hash(slot_hash)?
        .expect("l1 height should exist");

    if let Err(e) = ledger_db.insert_proof_data_by_l1_height(
        l1_height,
        tx_id_u8,
        proof,
        stored_state_transition,
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
    DB: ProverLedgerOps,
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
