use std::fmt::Debug;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use citrea_common::utils::{
    check_l2_range_exists, extract_sequencer_commitments, filter_out_proven_commitments,
};
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_db::ledger_db::ProverLedgerOps;
use sov_db::schema::types::BatchNumber;
use sov_modules_api::{SlotData, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec, SequencerCommitment};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::{StateTransitionData, ZkvmHost};
use sov_stf_runner::ProverService;
use tracing::error;

use super::RpcContext;
use crate::da_block_handler::{
    break_sequencer_commitments_into_groups, get_state_transition_data_from_commitments,
};

pub(super) async fn get_sequencer_commitments_for_proving<C, Da, Ps, Vm, DB, StateRoot, Witness>(
    context: Arc<RpcContext<C, Da, Ps, Vm, DB, StateRoot, Witness>>,
    l1_block: <Da as DaService>::FilteredBlock,
    group_commitments: Option<bool>,
) -> RpcResult<Vec<StateTransitionData<StateRoot, Witness, Da::Spec>>>
where
    C: sov_modules_api::Context,
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
    let l1_height = l1_block.header().height();

    let mut da_data: Vec<<<Da as DaService>::Spec as DaSpec>::BlobTransaction> =
        context.da_service.extract_relevant_blobs(&l1_block);

    let mut sequencer_commitments: Vec<SequencerCommitment> =
        extract_sequencer_commitments::<Da>(context.sequencer_da_pub_key.as_slice(), &mut da_data);

    if sequencer_commitments.is_empty() {
        return Err(ErrorObjectOwned::owned(
            INTERNAL_ERROR_CODE,
            INTERNAL_ERROR_MSG,
            Some(format!(
                "No sequencer commitments found in block: {l1_height}",
            )),
        ));
    }

    // Make sure all sequencer commitments are stored in ascending order.
    // We sort before checking ranges to prevent substraction errors.
    sequencer_commitments.sort();

    // If the L2 range does not exist, we break off the local loop getting back to
    // the outer loop / select to make room for other tasks to run.
    // We retry the L1 block there as well.
    let start_block_number = sequencer_commitments[0].l2_start_block_number;
    let end_block_number =
        sequencer_commitments[sequencer_commitments.len() - 1].l2_end_block_number;

    // If range is not synced yet return error
    if !check_l2_range_exists(&context.ledger, start_block_number, end_block_number) {
        return Err(ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(format!(
                    "L2 Range of commitments is not synced yet: {start_block_number} - {end_block_number}"
                )),
            ));
    }

    let (sequencer_commitments, preproven_commitments) =
        filter_out_proven_commitments(&context.ledger, &sequencer_commitments).map_err(|e| {
            error!("Error filtering out proven commitments: {:?}", e);
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(format!("{e}",)),
            )
        })?;

    if sequencer_commitments.is_empty() {
        return Err(ErrorObjectOwned::owned(
            INTERNAL_ERROR_CODE,
            INTERNAL_ERROR_MSG,
            Some(format!(
                "All sequencer commitments are duplicates from a former DA block {}",
                l1_height
            )),
        ));
    }

    let da_block_header_of_commitments: <<Da as DaService>::Spec as DaSpec>::BlockHeader =
        l1_block.header().clone();

    let ranges = match group_commitments {
        Some(true) => {
            break_sequencer_commitments_into_groups(&context.ledger, &sequencer_commitments)
                .map_err(|e| {
                    error!("Error breaking sequencer commitments into groups: {:?}", e);
                    ErrorObjectOwned::owned(
                        INTERNAL_ERROR_CODE,
                        INTERNAL_ERROR_MSG,
                        Some(format!("{e}",)),
                    )
                })?
        }
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
            &context.da_service,
            &context.ledger,
            &context.l1_block_cache,
        )
        .await
        .map_err(|e| {
            error!(
                "Error getting state transition data from commitments: {:?}",
                e
            );
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(format!("{e}",)),
            )
        })?;
        let initial_state_root = context
            .ledger
            .get_l2_state_root::<StateRoot>(first_l2_height_of_l1 - 1)
            .map_err(|e| {
                error!("Error getting initial state root: {:?}", e);
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("{e}",)),
                )
            })?
            .expect("There should be a state root");
        let initial_batch_hash = context
            .ledger
            .get_soft_confirmation_by_number(&BatchNumber(first_l2_height_of_l1))
            .map_err(|e| {
                error!("Error getting initial batch hash: {:?}", e);
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("{e}",)),
                )
            })?
            .ok_or(ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(format!(
                    "Could not find soft batch at height {}",
                    first_l2_height_of_l1
                )),
            ))?
            .prev_hash;

        let final_state_root = context
            .ledger
            .get_l2_state_root::<StateRoot>(last_l2_height_of_l1)
            .map_err(|e| {
                error!("Error getting final state root: {:?}", e);
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("{e}",)),
                )
            })?
            .expect("There should be a state root");

        let (inclusion_proof, completeness_proof) = context
            .da_service
            .get_extraction_proof(&l1_block, &da_data)
            .await;

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
                sequencer_public_key: context.sequencer_pub_key.clone(),
                sequencer_da_public_key: context.sequencer_da_pub_key.clone(),
            };

        state_transitions.push(state_transition_data);
    }

    Ok(state_transitions)
}
