use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use citrea_common::cache::L1BlockCache;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::ProverLedgerOps;
use sov_modules_api::{SpecId, Zkvm};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::ProverService;
use tokio::sync::Mutex;
use tracing::debug;

use crate::proving::{data_to_prove, prove_l1};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProverInputResponse {
    pub commitment_range: (u32, u32),
    pub l1_block_height: u64,
    pub encoded_serialized_state_transition_data: String,
}

pub(crate) struct RpcContext<C, Da, Ps, Vm, DB, StateRoot, Witness>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: ProverLedgerOps + Clone,
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
    pub da_service: Arc<Da>,
    pub prover_service: Arc<Ps>,
    pub ledger: DB,
    pub sequencer_da_pub_key: Vec<u8>,
    pub sequencer_pub_key: Vec<u8>,
    pub l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    pub code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    pub(crate) c: PhantomData<fn() -> C>,
    pub(crate) vm: PhantomData<fn() -> Vm>,
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

    /// Manually invoke proving.
    #[method(name = "prover_prove")]
    async fn prove(&self, l1_height: u64, group_commitments: Option<bool>) -> RpcResult<()>;
}

pub struct ProverRpcServerImpl<C, Da, Ps, Vm, DB, StateRoot, Witness>
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
    context: Arc<RpcContext<C, Da, Ps, Vm, DB, StateRoot, Witness>>,
}

impl<C, Da, Ps, Vm, DB, StateRoot, Witness>
    ProverRpcServerImpl<C, Da, Ps, Vm, DB, StateRoot, Witness>
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
    pub fn new(context: RpcContext<C, Da, Ps, Vm, DB, StateRoot, Witness>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl<C, Da, Ps, Vm, DB, StateRoot, Witness> ProverRpcServer
    for ProverRpcServerImpl<C, Da, Ps, Vm, DB, StateRoot, Witness>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: ProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
    Ps: ProverService<Vm, DaService = Da, StateRoot = StateRoot, Witness = Witness>
        + Send
        + Sync
        + 'static,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug
        + Send
        + 'static,
    Witness:
        Default + BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned + Send + 'static,
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

        let (_, state_transitions) = data_to_prove::<Da, DB, StateRoot, Witness>(
            self.context.da_service.clone(),
            self.context.ledger.clone(),
            self.context.sequencer_pub_key.clone(),
            self.context.sequencer_da_pub_key.clone(),
            self.context.l1_block_cache.clone(),
            l1_block,
            group_commitments,
        )
        .await
        .map_err(|e| {
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(format!("{e}",)),
            )
        })?;

        let mut state_transition_responses = vec![];

        for state_transition_data in state_transitions {
            let range_start = state_transition_data.sequencer_commitments_range.0;
            let range_end = state_transition_data.sequencer_commitments_range.1;
            let serialized_state_transition = serialize_state_transition(state_transition_data);

            let response = ProverInputResponse {
                commitment_range: (range_start, range_end),
                l1_block_height: l1_height,
                encoded_serialized_state_transition_data: hex::encode(serialized_state_transition),
            };

            state_transition_responses.push(response);
        }

        Ok(state_transition_responses)
    }

    async fn prove(&self, l1_height: u64, group_commitments: Option<bool>) -> RpcResult<()> {
        debug!("Prover: prover_prove");

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

        let (sequencer_commitments, state_transitions) = data_to_prove(
            self.context.da_service.clone(),
            self.context.ledger.clone(),
            self.context.sequencer_pub_key.clone(),
            self.context.sequencer_da_pub_key.clone(),
            self.context.l1_block_cache.clone(),
            l1_block.clone(),
            group_commitments,
        )
        .await
        .map_err(|e| {
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(format!("{e}",)),
            )
        })?;

        prove_l1(
            self.context.da_service.clone(),
            self.context.prover_service.clone(),
            self.context.ledger.clone(),
            self.context.code_commitments_by_spec.clone(),
            l1_block,
            sequencer_commitments,
            state_transitions,
        )
        .await
        .map_err(|e| {
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(format!("{e}",)),
            )
        })?;

        Ok(())
    }
}

fn serialize_state_transition<T: BorshSerialize>(item: T) -> Vec<u8> {
    borsh::to_vec(&item).expect("Risc0 hint serialization is infallible")
}

pub fn create_rpc_module<C, Da, Ps, Vm, DB, StateRoot, Witness>(
    rpc_context: RpcContext<C, Da, Ps, Vm, DB, StateRoot, Witness>,
) -> jsonrpsee::RpcModule<ProverRpcServerImpl<C, Da, Ps, Vm, DB, StateRoot, Witness>>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: ProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
    Ps: ProverService<Vm, DaService = Da, StateRoot = StateRoot, Witness = Witness>
        + Send
        + Sync
        + 'static,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug
        + Send
        + 'static,
    Witness:
        Default + BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned + Send + 'static,
{
    let server = ProverRpcServerImpl::new(rpc_context);

    ProverRpcServer::into_rpc(server)
}
