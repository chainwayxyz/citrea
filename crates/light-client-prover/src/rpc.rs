//! RPC interface for the light client prover
//!
//! This module provides a subset of the light client prover's RPC functionality,
//! specifically getting light client proofs by L1 height, getting batch proof method IDs,
//! and creating read-only light client circuit inputs by L1 height.
use std::collections::HashMap;
use std::sync::Arc;

use alloy_primitives::U64;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use citrea_common::rpc::utils::internal_rpc_error;
use citrea_common::LightClientProverConfig;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use sov_db::ledger_db::LightClientProverLedgerOps;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{Spec, SpecId, WorkingSet, Zkvm};
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::rpc::{BatchProofMethodIdRpcResponse, LightClientProofResponse};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::Network;
use sov_state::ProverStorage;

use crate::circuit::accessors::BatchProofMethodIdAccessor;
use crate::circuit::initial_values::InitialValueProvider;
use crate::circuit::LightClientProofCircuit;
use crate::input_builder::build_circuit_input_from_l1_block;

/// Context containing shared data needed for RPC method implementations
pub struct RpcContext<Da, DB, Vm>
where
    Da: DaService,
    DB: LightClientProverLedgerOps + Clone,
    Vm: Zkvm,
{
    /// The Citrea network this light client prover is running on.
    pub network: Network,
    /// Light client prover configuration.
    pub prover_config: LightClientProverConfig,
    /// Database for ledger operations
    pub ledger: DB,
    /// Database for storage operations
    pub storage: <DefaultContext as Spec>::Storage,
    /// Storage manager for read-only snapshot input generation.
    pub storage_manager: ProverStorageManager,
    /// Data availability service instance used to fetch L1 blocks.
    pub da_service: Arc<Da>,
    /// Code commitments for light client proof circuits by spec ID.
    pub code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
}

/// Creates a shared RpcContext with all required data.
///
/// # Arguments
/// * `ledger_db` - Database instance for ledger operations
/// * `storage` - Database for storage operations
pub fn create_rpc_context<Da, DB, Vm>(
    network: Network,
    prover_config: LightClientProverConfig,
    ledger_db: DB,
    storage: <DefaultContext as Spec>::Storage,
    storage_manager: ProverStorageManager,
    da_service: Arc<Da>,
    code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
) -> RpcContext<Da, DB, Vm>
where
    Da: DaService,
    DB: LightClientProverLedgerOps + Clone,
    Vm: Zkvm,
{
    RpcContext {
        network,
        prover_config,
        ledger: ledger_db,
        storage,
        storage_manager,
        da_service,
        code_commitments,
    }
}

/// Creates an RPC module with fullnode methods
///
/// # Arguments
/// * `rpc_context` - Context containing shared data for RPC methods
///
/// # Type Parameters
/// * `DB` - Database type implementing `LightClientProverLedgerOps`
pub fn create_rpc_module<Da, DB, Vm>(
    rpc_context: RpcContext<Da, DB, Vm>,
) -> jsonrpsee::RpcModule<LightClientProverRpcServerImpl<Da, DB, Vm>>
where
    Da: DaService,
    DB: LightClientProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: Zkvm + Send + Sync + 'static,
    Vm::CodeCommitment: Send + Sync,
    Network: InitialValueProvider<Da::Spec>,
{
    let server = LightClientProverRpcServerImpl::new(rpc_context);

    LightClientProverRpcServer::into_rpc(server)
}

/// Updates the given RpcModule with Prover methods.
pub fn register_rpc_methods<Da, DB, Vm>(
    mut rpc_methods: jsonrpsee::RpcModule<()>,
    rpc_context: RpcContext<Da, DB, Vm>,
) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError>
where
    Da: DaService,
    DB: LightClientProverLedgerOps + Clone + 'static,
    Vm: Zkvm + Send + Sync + 'static,
    Vm::CodeCommitment: Send + Sync,
    Network: InitialValueProvider<Da::Spec>,
{
    let rpc = create_rpc_module(rpc_context);
    rpc_methods.merge(rpc)?;
    Ok(rpc_methods)
}

#[rpc(client, server, namespace = "lightClientProver")]
pub trait LightClientProverRpc {
    /// Generate state transition data for the given L1 block height, and return the data as a borsh serialized hex string.
    ///
    /// # Arguments
    /// * `l1_height` - The L1 block height for which to get the light client proof.
    #[method(name = "getLightClientProofByL1Height")]
    async fn get_light_client_proof_by_l1_height(
        &self,
        l1_height: U64,
    ) -> RpcResult<Option<LightClientProofResponse>>;

    /// Gets the current method ids saved light client provers jmt state
    #[method(name = "getBatchProofMethodIds")]
    async fn get_batch_proof_method_ids(&self) -> RpcResult<Vec<BatchProofMethodIdRpcResponse>>;

    /// Creates the read-only light client circuit input for the given L1 block height.
    ///
    /// The returned string is base64-encoded Borsh bytes of `LightClientCircuitInput`.
    #[method(name = "createCircuitInput")]
    async fn create_circuit_input(&self, l1_height: U64) -> RpcResult<String>;
}

/// Server implementation of the light client prover RPC interface
pub struct LightClientProverRpcServerImpl<Da, DB, Vm>
where
    Da: DaService,
    DB: LightClientProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: Zkvm + Send + Sync + 'static,
{
    /// Context containing shared data needed for RPC method implementations
    pub context: Arc<RpcContext<Da, DB, Vm>>,
}

impl<Da, DB, Vm> LightClientProverRpcServerImpl<Da, DB, Vm>
where
    Da: DaService,
    DB: LightClientProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: Zkvm + Send + Sync + 'static,
    Vm::CodeCommitment: Send + Sync,
    Network: InitialValueProvider<Da::Spec>,
{
    /// Creates a new light client prover RPC server instance
    ///
    /// # Arguments
    /// * `context` - Context containing shared data for RPC methods
    pub fn new(context: RpcContext<Da, DB, Vm>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }

    fn storage_for_l1_block(&self, l1_height: u64) -> anyhow::Result<ProverStorage> {
        let initial_da_height = self.context.prover_config.initial_da_height;
        if l1_height < initial_da_height {
            anyhow::bail!(
                "Cannot build light client input for L1 block #{} before initial DA height #{}",
                l1_height,
                initial_da_height
            );
        }

        if let Some(last_scanned_l1_height) = self
            .context
            .ledger
            .get_last_scanned_l1_height()?
            .map(|h| h.0)
        {
            let max_request_height = last_scanned_l1_height + 1;
            if l1_height > max_request_height {
                anyhow::bail!(
                    "Cannot build light client input for future L1 block #{}; last scanned L1 block is #{}",
                    l1_height,
                    last_scanned_l1_height
                );
            }
        } else if l1_height != initial_da_height {
            anyhow::bail!(
                "Cannot build light client input for L1 block #{} before initial L1 block #{} has been processed",
                l1_height,
                initial_da_height
            );
        }

        Ok(self
            .context
            .storage_manager
            .create_storage_for_l2_height(l1_height - initial_da_height))
    }
}

#[async_trait::async_trait]
impl<Da, DB, Vm> LightClientProverRpcServer for LightClientProverRpcServerImpl<Da, DB, Vm>
where
    Da: DaService,
    DB: LightClientProverLedgerOps + Clone + Send + Sync + 'static,
    Vm: Zkvm + Send + Sync + 'static,
    Vm::CodeCommitment: Send + Sync,
    Network: InitialValueProvider<Da::Spec>,
{
    async fn get_light_client_proof_by_l1_height(
        &self,
        l1_height: U64,
    ) -> RpcResult<Option<LightClientProofResponse>> {
        let proof = self
            .context
            .ledger
            .get_light_client_proof_data_by_l1_height(l1_height.to())
            .map_err(internal_rpc_error)?;
        let Some(proof) = proof else {
            return Ok(None);
        };

        let info = self
            .context
            .ledger
            .get_proving_session_info_by_l1_height(l1_height.to())
            .map_err(internal_rpc_error)?;

        let response = LightClientProofResponse {
            proof: proof.proof,
            light_client_proof_output: proof.light_client_proof_output.into(),
            info,
        };
        Ok(Some(response))
    }

    async fn get_batch_proof_method_ids(&self) -> RpcResult<Vec<BatchProofMethodIdRpcResponse>> {
        let mut working_set = WorkingSet::new(self.context.storage.clone());

        let method_ids = BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set)
            .unwrap_or_default()
            .into_iter()
            .map(|id| BatchProofMethodIdRpcResponse {
                height: alloy_primitives::U64::from(id.0),
                method_id: id.1.into(),
            })
            .collect::<Vec<_>>();

        Ok(method_ids)
    }

    async fn create_circuit_input(&self, l1_height: U64) -> RpcResult<String> {
        let l1_height = l1_height.to();
        let storage = self
            .storage_for_l1_block(l1_height)
            .map_err(internal_rpc_error)?;

        let l1_block = self
            .context
            .da_service
            .get_block_at(l1_height)
            .await
            .map_err(internal_rpc_error)?;

        let circuit = LightClientProofCircuit::<ProverStorage, Da::Spec, Vm>::new();
        let prepared = build_circuit_input_from_l1_block::<Da, DB, Vm>(
            self.context.network,
            &self.context.prover_config,
            self.context.da_service.as_ref(),
            &self.context.ledger,
            &self.context.code_commitments,
            &circuit,
            &l1_block,
            storage,
        )
        .map_err(internal_rpc_error)?;

        let raw_input = borsh::to_vec(&prepared.circuit_input).map_err(internal_rpc_error)?;
        Ok(BASE64_STANDARD.encode(raw_input))
    }
}
