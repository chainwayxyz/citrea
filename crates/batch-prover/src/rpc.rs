#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

use alloy_primitives::{U32, U64};
use citrea_common::cache::L1BlockCache;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use prover_services::ParallelProverService;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_keys::default_signature::K256PublicKey;
use sov_modules_api::{SpecId, Zkvm};
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::ZkvmHost;
use tokio::sync::Mutex;

use crate::partition::PartitionMode;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProverInputResponse {
    pub commitment_range: (U32, U32),
    pub l1_block_height: U64,
    pub encoded_serialized_batch_proof_input: String,
}

pub struct RpcContext<Da, Vm, DB>
where
    // C: sov_modules_api::Context,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone,
    Vm: ZkvmHost + Zkvm + 'static,
{
    pub da_service: Arc<Da>,
    pub prover_service: Arc<ParallelProverService<Da, Vm>>,
    pub ledger: DB,
    pub storage_manager: ProverStorageManager,
    pub sequencer_da_pub_key: Vec<u8>,
    pub sequencer_pub_key: K256PublicKey,
    pub l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    pub code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    pub elfs_by_spec: HashMap<SpecId, Vec<u8>>,
    pub(crate) phantom_vm: PhantomData<fn() -> Vm>,
}

/// Creates a shared RpcContext with all required data.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn create_rpc_context<Da, Vm, DB>(
    da_service: Arc<Da>,
    prover_service: Arc<ParallelProverService<Da, Vm>>,
    ledger: DB,
    storage_manager: ProverStorageManager,
    sequencer_da_pub_key: Vec<u8>,
    sequencer_pub_key: K256PublicKey,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    elfs_by_spec: HashMap<SpecId, Vec<u8>>,
) -> RpcContext<Da, Vm, DB>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone,
    Vm: ZkvmHost + Zkvm,
{
    RpcContext {
        ledger,
        da_service,
        storage_manager,
        sequencer_da_pub_key,
        sequencer_pub_key,
        l1_block_cache,
        prover_service,
        code_commitments_by_spec,
        elfs_by_spec,
        phantom_vm: std::marker::PhantomData,
    }
}

/// Updates the given RpcModule with Prover methods.
pub fn register_rpc_methods<Da, Vm, DB>(
    rpc_context: RpcContext<Da, Vm, DB>,
    mut rpc_methods: jsonrpsee::RpcModule<()>,
) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
{
    let rpc = create_rpc_module::<Da, Vm, DB>(rpc_context);
    rpc_methods.merge(rpc)?;
    Ok(rpc_methods)
}

#[rpc(client, server, namespace = "batchProver")]
pub trait BatchProverRpc {
    /// Manually signal proving. This rpc triggers a proving signal with the difference that sampling will be ignored.
    #[method(name = "prove")]
    async fn prove(&self) -> RpcResult<()>;
}

pub struct BatchProverRpcServerImpl<Da, Vm, DB>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
{
    context: Arc<RpcContext<Da, Vm, DB>>,
}

impl<Da, Vm, DB> BatchProverRpcServerImpl<Da, Vm, DB>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm,
{
    pub fn new(context: RpcContext<Da, Vm, DB>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl<Da, Vm, DB> BatchProverRpcServer for BatchProverRpcServerImpl<Da, Vm, DB>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
{
    async fn prove(&self) -> RpcResult<()> {
        // let l1_block: <Da as DaService>::FilteredBlock = self
        //     .context
        //     .da_service
        //     .get_block_at(l1_height)
        //     .await
        //     .map_err(|e| {
        //         ErrorObjectOwned::owned(
        //             INTERNAL_ERROR_CODE,
        //             INTERNAL_ERROR_MSG,
        //             Some(format!("{e}",)),
        //         )
        //     })?;

        // let (sequencer_commitments, inputs) = data_to_prove::<Da, DB>(
        //     self.context.da_service.clone(),
        //     self.context.ledger.clone(),
        //     &self.context.storage_manager,
        //     self.context.sequencer_pub_key.clone(),
        //     self.context.sequencer_da_pub_key.clone(),
        //     &l1_block,
        //     group_commitments,
        // )
        // .await
        // .map_err(|e| {
        //     ErrorObjectOwned::owned(
        //         INTERNAL_ERROR_CODE,
        //         INTERNAL_ERROR_MSG,
        //         Some(format!("{e}",)),
        //     )
        // })?;

        // prove_l1::<Da, Vm, DB>(
        //     self.context.prover_service.clone(),
        //     self.context.ledger.clone(),
        //     self.context.code_commitments_by_spec.clone(),
        //     self.context.elfs_by_spec.clone(),
        //     &l1_block,
        //     sequencer_commitments,
        //     inputs,
        // )
        // .await
        // .map_err(|e| {
        //     ErrorObjectOwned::owned(
        //         INTERNAL_ERROR_CODE,
        //         INTERNAL_ERROR_MSG,
        //         Some(format!("{e}",)),
        //     )
        // })?;

        // Ok(())
        todo!()
    }
}

pub fn create_rpc_module<Da, Vm, DB>(
    rpc_context: RpcContext<Da, Vm, DB>,
) -> jsonrpsee::RpcModule<BatchProverRpcServerImpl<Da, Vm, DB>>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
{
    let server = BatchProverRpcServerImpl::new(rpc_context);

    BatchProverRpcServer::into_rpc(server)
}
