use std::marker::PhantomData;
use std::sync::Arc;

use borsh::BorshSerialize;
use citrea_common::cache::L1BlockCache;
use citrea_common::utils::{
    check_l2_range_exists, extract_sequencer_commitments, filter_out_proven_commitments,
};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::BatchNumber;
use sov_modules_core::{Spec, Storage};
use sov_rollup_interface::da::{DaSpec, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::zk::StateTransitionData;
use tokio::sync::Mutex;
use tracing::{debug, error};

use crate::da_block_handler::{
    break_sequencer_commitments_into_groups, get_state_transition_data_from_commitments,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProverInputResponse {
    pub commitment_range: (u32, u32),
    pub l1_block_height: u64,
    pub encoded_serialized_state_transition_data: String,
}

pub(crate) struct RpcContext<C, Da, DB>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps,
{
    pub da_service: Arc<Da>,
    pub ledger: DB,
    pub sequencer_da_pub_key: Vec<u8>,
    pub sequencer_pub_key: Vec<u8>,
    pub l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    pub phantom: PhantomData<fn() -> C>,
}

#[rpc(client, server)]
pub trait ProverRpc {
    /// Generate state transition data for the given L1 block height, and return the data as a borsh serialized hex string.
    #[method(name = "prover_generateInput")]
    async fn generate_input(
        &self,
        l1_height: u64,
        group_commitments: Option<bool>,
    ) -> RpcResult<Vec<ProverInputResponse>>;
}

pub struct ProverRpcServerImpl<C, Da, DB>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Send + Sync + 'static,
{
    context: Arc<RpcContext<C, Da, DB>>,
}

impl<C, Da, DB> ProverRpcServerImpl<C, Da, DB>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Send + Sync + 'static,
{
    pub fn new(context: RpcContext<C, Da, DB>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl<
        C: sov_modules_api::Context,
        Da: DaService,
        DB: BatchProverLedgerOps + Send + Sync + 'static,
    > ProverRpcServer for ProverRpcServerImpl<C, Da, DB>
{
    async fn generate_input(
        &self,
        l1_height: u64,
        group_commitments: Option<bool>,
    ) -> RpcResult<Vec<ProverInputResponse>> {
        debug!("Prover: prover_generateInput");

        let l1_block: <Da as DaService>::FilteredBlock = self
            .context
            .da_service
            .get_block_at(l1_height)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("{e}",)),
                )
            })?;

        let mut da_data: Vec<<<Da as DaService>::Spec as DaSpec>::BlobTransaction> =
            self.context.da_service.extract_relevant_blobs(&l1_block);

        let mut sequencer_commitments: Vec<SequencerCommitment> = extract_sequencer_commitments::<Da>(
            self.context.sequencer_da_pub_key.as_slice(),
            &mut da_data,
        );

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
        if !check_l2_range_exists(&self.context.ledger, start_block_number, end_block_number) {
            return Err(ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(format!(
                    "L2 Range of commitments is not synced yet: {start_block_number} - {end_block_number}"
                )),
            ));
        }

        let (sequencer_commitments, preproven_commitments) =
            filter_out_proven_commitments(&self.context.ledger, &sequencer_commitments).map_err(
                |e| {
                    error!("Error filtering out proven commitments: {:?}", e);
                    ErrorObjectOwned::owned(
                        INTERNAL_ERROR_CODE,
                        INTERNAL_ERROR_MSG,
                        Some(format!("{e}",)),
                    )
                },
            )?;

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

        let mut state_transition_responses = Vec::new();

        let ranges = match group_commitments {
            Some(true) => break_sequencer_commitments_into_groups(
                &self.context.ledger,
                &sequencer_commitments,
            )
            .map_err(|e| {
                error!("Error breaking sequencer commitments into groups: {:?}", e);
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("{e}",)),
                )
            })?,
            _ => vec![(0..=sequencer_commitments.len() - 1)],
        };

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
                &self.context.da_service,
                &self.context.ledger,
                &self.context.l1_block_cache,
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
            let initial_state_root = self
                .context
                .ledger
                .get_l2_state_root::<<<C as Spec>::Storage as Storage>::Root>(
                    first_l2_height_of_l1 - 1,
                )
                .map_err(|e| {
                    error!("Error getting initial state root: {:?}", e);
                    ErrorObjectOwned::owned(
                        INTERNAL_ERROR_CODE,
                        INTERNAL_ERROR_MSG,
                        Some(format!("{e}",)),
                    )
                })?
                .expect("There should be a state root");
            let initial_batch_hash = self
                .context
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

            let final_state_root = self
                .context
                .ledger
                .get_l2_state_root::<<<C as Spec>::Storage as Storage>::Root>(last_l2_height_of_l1)
                .map_err(|e| {
                    error!("Error getting final state root: {:?}", e);
                    ErrorObjectOwned::owned(
                        INTERNAL_ERROR_CODE,
                        INTERNAL_ERROR_MSG,
                        Some(format!("{e}",)),
                    )
                })?
                .expect("There should be a state root");

            let (inclusion_proof, completeness_proof) = self
                .context
                .da_service
                .get_extraction_proof(&l1_block, &da_data)
                .await;

            let state_transition_data: StateTransitionData<
                <<C as Spec>::Storage as Storage>::Root,
                <<C as Spec>::Storage as Storage>::Witness,
                Da::Spec,
            > = StateTransitionData {
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
                sequencer_public_key: self.context.sequencer_pub_key.clone(),
                sequencer_da_public_key: self.context.sequencer_da_pub_key.clone(),
            };
            let serialized_state_transition = serialize_state_transition(state_transition_data);

            let response = ProverInputResponse {
                commitment_range: (
                    *sequencer_commitments_range.start() as u32,
                    *sequencer_commitments_range.end() as u32,
                ),
                l1_block_height: l1_height,
                encoded_serialized_state_transition_data: hex::encode(serialized_state_transition),
            };

            state_transition_responses.push(response);
        }

        Ok(state_transition_responses)
    }
}

fn serialize_state_transition<T: BorshSerialize>(item: T) -> Vec<u8> {
    borsh::to_vec(&item).expect("Risc0 hint serialization is infallible")
}

pub fn create_rpc_module<C, Da, DB>(
    rpc_context: RpcContext<C, Da, DB>,
) -> jsonrpsee::RpcModule<ProverRpcServerImpl<C, Da, DB>>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Send + Sync + 'static,
{
    let server = ProverRpcServerImpl::new(rpc_context);

    ProverRpcServer::into_rpc(server)
}
