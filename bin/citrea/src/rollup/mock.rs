use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use citrea_common::backup::{create_backup_rpc_module, BackupManager};
// use citrea_sp1::host::SP1Host;
use citrea_common::config::risc0::Risc0HostConfig;
use citrea_common::config::ProverGuestRunConfig;
use citrea_common::{FullNodeConfig, NodeType, RpcConfig};
use citrea_primitives::forks::use_network_forks;
use citrea_risc0_adapter::host::Risc0Host;
use citrea_stf::genesis_config::StorageConfig;
use citrea_stf::runtime::CitreaRuntime;
use prover_services::{ParallelProverService, ProofGenMode};
use reth_tasks::TaskExecutor;
use sov_db::ledger_db::LedgerDB;
use sov_mock_da::{MockDaConfig, MockDaService, MockDaSpec, MockDaVerifier};
use sov_modules_api::default_context::NativeContext;
use sov_modules_api::{Spec, SpecId, Zkvm};
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::Runtime;
use sov_prover_storage_manager::ProverStorageManager;

use crate::guests::{BATCH_PROOF_LATEST_MOCK_GUESTS, LIGHT_CLIENT_LATEST_MOCK_GUESTS};
use crate::{CitreaRollupBlueprint, Network};

/// Rollup with MockDa
pub struct MockDemoRollup {
    network: Network,
}

impl CitreaRollupBlueprint for MockDemoRollup {}

#[async_trait]
impl RollupBlueprint for MockDemoRollup {
    type DaService = MockDaService;
    type DaSpec = MockDaSpec;
    type DaConfig = MockDaConfig;
    type DaVerifier = MockDaVerifier;
    type Vm = Risc0Host;

    fn new(network: Network) -> Self {
        use_network_forks(network);
        Self { network }
    }

    fn create_rpc_methods(
        &self,
        _node_type: NodeType,
        storage: <NativeContext as Spec>::Storage,
        ledger_db: &LedgerDB,
        _da_service: &Arc<Self::DaService>,
        backup_manager: &Arc<BackupManager>,
        rpc_config: RpcConfig,
    ) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error> {
        // runtime rpc.
        let mut rpc_methods =
            <CitreaRuntime<NativeContext, Self::DaSpec>>::rpc_methods(storage, ledger_db.clone());

        // ledger rpc.
        let ledger_db_methods = sov_ledger_rpc::server::create_rpc_module::<LedgerDB>(
            ledger_db.clone(),
            rpc_config.into(),
        );
        rpc_methods.merge(ledger_db_methods)?;

        let backup_methods = create_backup_rpc_module(ledger_db.clone(), backup_manager.clone());
        rpc_methods.merge(backup_methods)?;

        Ok(rpc_methods)
    }

    async fn create_da_service(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        _require_wallet_check: bool,
        _task_manager: TaskExecutor,
        _network: Network,
    ) -> Result<Arc<Self::DaService>, anyhow::Error> {
        Ok(Arc::new(MockDaService::new(
            rollup_config.da.sender_address.clone(),
            &rollup_config.da.db_path,
        )))
    }

    fn get_batch_proof_elfs(&self) -> HashMap<SpecId, Vec<u8>> {
        BATCH_PROOF_LATEST_MOCK_GUESTS
            .iter()
            .map(|(k, (_, code))| (*k, code.clone()))
            .collect()
    }

    fn get_light_client_elfs(&self) -> HashMap<SpecId, Vec<u8>> {
        LIGHT_CLIENT_LATEST_MOCK_GUESTS
            .iter()
            .map(|(k, (_, code))| (*k, code.clone()))
            .collect()
    }

    fn get_batch_proof_code_commitments(
        &self,
    ) -> HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment> {
        BATCH_PROOF_LATEST_MOCK_GUESTS
            .iter()
            .map(|(k, (id, _))| (*k, *id))
            .collect()
    }

    fn get_light_client_proof_code_commitments(
        &self,
    ) -> HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment> {
        LIGHT_CLIENT_LATEST_MOCK_GUESTS
            .iter()
            .map(|(k, (id, _))| (*k, *id))
            .collect()
    }

    async fn create_prover_service(
        &self,
        proving_mode: ProverGuestRunConfig,
        risc0_host_config: Risc0HostConfig,
        da_service: &Arc<Self::DaService>,
        ledger_db: LedgerDB,
        proof_sampling_number: usize,
        is_light_client_prover: bool,
    ) -> ParallelProverService<Self::DaService, Self::Vm> {
        let vm = Risc0Host::new(ledger_db.clone(), self.network, risc0_host_config).await;

        let proof_mode = match proving_mode {
            ProverGuestRunConfig::Skip => ProofGenMode::Skip,
            ProverGuestRunConfig::Execute => ProofGenMode::Execute,
            ProverGuestRunConfig::Prove => ProofGenMode::ProveWithSampling,
            ProverGuestRunConfig::ProveWithFakeProofs => {
                ProofGenMode::ProveWithSamplingWithFakeProofs(proof_sampling_number)
            }
        };

        if is_light_client_prover {
            // Parallel proof limit should be 1 for light client prover
            ParallelProverService::new(da_service.clone(), vm, proof_mode, 1)
                .expect("Should be able to instantiate prover service")
        } else {
            ParallelProverService::new_from_env(da_service.clone(), vm, proof_mode)
                .expect("Should be able to instantiate prover service")
        }
    }

    fn create_storage_manager(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
    ) -> anyhow::Result<ProverStorageManager> {
        let storage_config = StorageConfig {
            path: rollup_config.storage.path.clone(),
            db_max_open_files: rollup_config.storage.db_max_open_files,
        };
        ProverStorageManager::new(storage_config)
    }
}
