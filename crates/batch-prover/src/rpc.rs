#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

use alloy_primitives::{U32, U64};
use borsh::{BorshDeserialize, BorshSerialize};
use citrea_common::cache::L1BlockCache;
use citrea_primitives::forks::fork_from_block_number;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_modules_api::{SpecId, Zkvm};
use sov_modules_stf_blueprint::Runtime;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::{BatchProofCircuitInputV1, ZkvmHost};
use sov_stf_runner::ProverService;
use tokio::sync::Mutex;

use crate::proving::{data_to_prove, prove_l1, GroupCommitments};
use crate::{StfStateRoot, StfTransaction, StfWitness};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProverInputResponse {
    pub commitment_range: (U32, U32),
    pub l1_block_height: U64,
    pub encoded_serialized_batch_proof_input: String,
}

pub struct RpcContext<C, Da, Ps, Vm, DB>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<DaService = Da> + Send + Sync,
{
    pub da_service: Arc<Da>,
    pub prover_service: Arc<Ps>,
    pub ledger: DB,
    pub sequencer_da_pub_key: Vec<u8>,
    pub sequencer_pub_key: Vec<u8>,
    pub l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    pub code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    pub elfs_by_spec: HashMap<SpecId, Vec<u8>>,
    pub(crate) phantom_c: PhantomData<fn() -> C>,
    pub(crate) phantom_vm: PhantomData<fn() -> Vm>,
}

/// Creates a shared RpcContext with all required data.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn create_rpc_context<C, Da, Ps, Vm, DB, RT>(
    da_service: Arc<Da>,
    prover_service: Arc<Ps>,
    ledger: DB,
    sequencer_da_pub_key: Vec<u8>,
    sequencer_pub_key: Vec<u8>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    elfs_by_spec: HashMap<SpecId, Vec<u8>>,
) -> RpcContext<C, Da, Ps, Vm, DB>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<DaService = Da> + Send + Sync,
    RT: Runtime<C, Da::Spec>,
{
    RpcContext {
        ledger: ledger.clone(),
        da_service: da_service.clone(),
        sequencer_da_pub_key: sequencer_da_pub_key.clone(),
        sequencer_pub_key: sequencer_pub_key.clone(),
        l1_block_cache: l1_block_cache.clone(),
        prover_service: prover_service.clone(),
        code_commitments_by_spec: code_commitments_by_spec.clone(),
        elfs_by_spec: elfs_by_spec.clone(),
        phantom_c: std::marker::PhantomData,
        phantom_vm: std::marker::PhantomData,
    }
}

/// Updates the given RpcModule with Prover methods.
pub fn register_rpc_methods<C, Da, Ps, Vm, DB, RT>(
    rpc_context: RpcContext<C, Da, Ps, Vm, DB>,
    mut rpc_methods: jsonrpsee::RpcModule<()>,
) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
    Ps: ProverService<DaService = Da> + Send + Sync + 'static,
    RT: Runtime<C, Da::Spec>,
{
    let rpc = create_rpc_module::<
        C,
        Da,
        Ps,
        Vm,
        DB,
        StfStateRoot<C, Da::Spec, RT>,
        StfWitness<C, Da::Spec, RT>,
        StfTransaction<C, Da::Spec, RT>,
    >(rpc_context);
    rpc_methods.merge(rpc)?;
    Ok(rpc_methods)
}

#[rpc(client, server, namespace = "batchProver")]
pub trait BatchProverRpc {
    /// Generate state transition data for the given L1 block height, and return the data as a borsh serialized hex string.
    #[method(name = "generateInput")]
    async fn generate_input(
        &self,
        l1_height: u64,
        group_commitments: Option<GroupCommitments>,
    ) -> RpcResult<Vec<ProverInputResponse>>;

    /// Manually invoke proving.
    #[method(name = "prove")]
    async fn prove(
        &self,
        l1_height: u64,
        group_commitments: Option<GroupCommitments>,
    ) -> RpcResult<()>;
}

pub struct BatchProverRpcServerImpl<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<DaService = Da> + Send + Sync,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
    Witness: Default + BorshDeserialize + Serialize + DeserializeOwned,
{
    context: Arc<RpcContext<C, Da, Ps, Vm, DB>>,
    _state_root: PhantomData<StateRoot>,
    _witness: PhantomData<Witness>,
    _tx: PhantomData<Tx>,
}

impl<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>
    BatchProverRpcServerImpl<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<DaService = Da> + Send + Sync,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug
        + Send
        + Sync,
    Witness: Default + BorshDeserialize + Serialize + DeserializeOwned + Send + Sync,
{
    pub fn new(context: RpcContext<C, Da, Ps, Vm, DB>) -> Self {
        Self {
            context: Arc::new(context),
            _state_root: PhantomData,
            _witness: PhantomData,
            _tx: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx> BatchProverRpcServer
    for BatchProverRpcServerImpl<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
    Ps: ProverService<DaService = Da> + Send + Sync + 'static,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug
        + Send
        + Sync
        + 'static,
    Witness: Default
        + BorshSerialize
        + BorshDeserialize
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static,
    Tx: Clone + BorshSerialize + BorshDeserialize + Send + Sync + 'static,
{
    async fn generate_input(
        &self,
        l1_height: u64,
        group_commitments: Option<GroupCommitments>,
    ) -> RpcResult<Vec<ProverInputResponse>> {
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

        let (sequencer_commitments, inputs) = data_to_prove::<Da, DB, StateRoot, Witness, Tx>(
            self.context.da_service.clone(),
            self.context.ledger.clone(),
            self.context.sequencer_pub_key.clone(),
            self.context.sequencer_da_pub_key.clone(),
            self.context.l1_block_cache.clone(),
            &l1_block,
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

        let mut batch_proof_circuit_input_responses = vec![];

        for input in inputs {
            let range_start = input.sequencer_commitments_range.0;
            let range_end = input.sequencer_commitments_range.1;

            let last_seq_com = sequencer_commitments
                .get(range_end as usize)
                .expect("Commitment does not exist");
            let last_l2_height = last_seq_com.l2_end_block_number;
            let current_spec = fork_from_block_number(last_l2_height).spec_id;

            let serialized_circuit_input = match current_spec {
                SpecId::Genesis => borsh::to_vec(&BatchProofCircuitInputV1::from(input)),
                _ => borsh::to_vec(&input),
            }
            .expect("Risc0 hint serialization is infallible");

            let response = ProverInputResponse {
                commitment_range: (U32::from(range_start), U32::from(range_end)),
                l1_block_height: U64::from(l1_height),
                encoded_serialized_batch_proof_input: format!(
                    "0x{}",
                    faster_hex::hex_string(&serialized_circuit_input)
                ),
            };

            batch_proof_circuit_input_responses.push(response);
        }

        Ok(batch_proof_circuit_input_responses)
    }

    async fn prove(
        &self,
        l1_height: u64,
        group_commitments: Option<GroupCommitments>,
    ) -> RpcResult<()> {
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

        let (sequencer_commitments, inputs) = data_to_prove::<Da, DB, StateRoot, Witness, Tx>(
            self.context.da_service.clone(),
            self.context.ledger.clone(),
            self.context.sequencer_pub_key.clone(),
            self.context.sequencer_da_pub_key.clone(),
            self.context.l1_block_cache.clone(),
            &l1_block,
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

        prove_l1::<Da, Ps, Vm, DB, StateRoot, Witness, Tx>(
            self.context.prover_service.clone(),
            self.context.ledger.clone(),
            self.context.code_commitments_by_spec.clone(),
            self.context.elfs_by_spec.clone(),
            &l1_block,
            sequencer_commitments,
            inputs,
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

pub fn create_rpc_module<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>(
    rpc_context: RpcContext<C, Da, Ps, Vm, DB>,
) -> jsonrpsee::RpcModule<BatchProverRpcServerImpl<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
    Ps: ProverService<DaService = Da> + Send + Sync + 'static,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug
        + Send
        + Sync
        + 'static,
    Witness: Default
        + BorshSerialize
        + BorshDeserialize
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static,
    Tx: Clone + BorshSerialize + BorshDeserialize + Send + Sync + 'static,
{
    let server = BatchProverRpcServerImpl::new(rpc_context);

    BatchProverRpcServer::into_rpc(server)
}
