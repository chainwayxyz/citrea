#![allow(clippy::type_complexity)]

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
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_modules_api::{SpecId, Zkvm};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::ProverService;
use tokio::sync::Mutex;

use crate::proving::{data_to_prove, prove_l1, GroupCommitments};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProverInputResponse {
    pub commitment_range: (u32, u32),
    pub l1_block_height: u64,
    pub encoded_serialized_batch_proof_input: String,
}

pub struct RpcContext<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<DaService = Da>,
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
    pub elfs_by_spec: HashMap<SpecId, Vec<u8>>,
    pub(crate) phantom_c: PhantomData<fn() -> C>,
    pub(crate) phantom_vm: PhantomData<fn() -> Vm>,
    pub(crate) phantom_sr: PhantomData<fn() -> StateRoot>,
    pub(crate) phantom_w: PhantomData<fn() -> Witness>,
    pub(crate) phantom_tx: PhantomData<fn() -> Tx>,
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
    Ps: ProverService<DaService = Da>,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
    Witness: Default + BorshDeserialize + Serialize + DeserializeOwned,
{
    context: Arc<RpcContext<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>>,
}

impl<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>
    BatchProverRpcServerImpl<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>
where
    C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<DaService = Da>,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
    Witness: Default + BorshDeserialize + Serialize + DeserializeOwned,
{
    pub fn new(context: RpcContext<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>) -> Self {
        Self {
            context: Arc::new(context),
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
        + 'static,
    Witness:
        Default + BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned + Send + 'static,
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

        let (_, inputs) = data_to_prove::<Da, DB, StateRoot, Witness, Tx>(
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

        let mut batch_proof_circuit_input_responses = vec![];

        for input in inputs {
            let range_start = input.sequencer_commitments_range.0;
            let range_end = input.sequencer_commitments_range.1;
            let serialized_circuit_input = serialize_batch_proof_circuit_input(input);

            let response = ProverInputResponse {
                commitment_range: (range_start, range_end),
                l1_block_height: l1_height,
                encoded_serialized_batch_proof_input: hex::encode(serialized_circuit_input),
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

        prove_l1::<Da, Ps, Vm, DB, StateRoot, Witness, Tx>(
            self.context.prover_service.clone(),
            self.context.ledger.clone(),
            self.context.code_commitments_by_spec.clone(),
            self.context.elfs_by_spec.clone(),
            l1_block,
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

fn serialize_batch_proof_circuit_input<T: BorshSerialize>(item: T) -> Vec<u8> {
    borsh::to_vec(&item).expect("Risc0 hint serialization is infallible")
}

pub fn create_rpc_module<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>(
    rpc_context: RpcContext<C, Da, Ps, Vm, DB, StateRoot, Witness, Tx>,
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
        + 'static,
    Witness:
        Default + BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned + Send + 'static,
    Tx: Clone + BorshSerialize + BorshDeserialize + Send + Sync + 'static,
{
    let server = BatchProverRpcServerImpl::new(rpc_context);

    BatchProverRpcServer::into_rpc(server)
}
