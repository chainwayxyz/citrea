use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use citrea_common::backup::{create_backup_rpc_module, BackupManager};
use citrea_common::config::ProverGuestRunConfig;
use citrea_common::rpc::register_healthcheck_rpc;
use citrea_common::FullNodeConfig;
use citrea_primitives::forks::use_network_forks;
// use citrea_sp1::host::SP1Host;
use citrea_risc0_adapter::host::Risc0BonsaiHost;
use citrea_stf::genesis_config::StorageConfig;
use citrea_stf::runtime::CitreaRuntime;
use prover_services::{ParallelProverService, ProofGenMode};
use reth_tasks::TaskExecutor;
use sov_db::ledger_db::LedgerDB;
use sov_mock_da::{MockDaConfig, MockDaService, MockDaSpec, MockDaVerifier};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{Address, Spec, SpecId, Zkvm};
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use tokio::sync::broadcast;

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
    type Vm = Risc0BonsaiHost;

    fn new(network: Network) -> Self {
        use_network_forks(network);
        Self { network }
    }

    fn create_rpc_methods(
        &self,
        storage: <DefaultContext as Spec>::Storage,
        ledger_db: &LedgerDB,
        da_service: &Arc<Self::DaService>,
        sequencer_client_url: Option<String>,
        l2_block_rx: Option<broadcast::Receiver<u64>>,
        backup_manager: &Arc<BackupManager>,
    ) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error> {
        // TODO set the sequencer address
        let sequencer = Address::new([0; 32]);

        let mut rpc_methods = sov_modules_rollup_blueprint::register_rpc::<
            Self::DaService,
            CitreaRuntime<DefaultContext, Self::DaSpec>,
        >(storage.clone(), ledger_db, sequencer)?;

        crate::eth::register_ethereum::<Self::DaService>(
            da_service.clone(),
            storage,
            ledger_db.clone(),
            &mut rpc_methods,
            sequencer_client_url,
            l2_block_rx,
        )?;

        register_healthcheck_rpc(&mut rpc_methods, ledger_db.clone())?;
        let backup_methods = create_backup_rpc_module(ledger_db.clone(), backup_manager.clone());
        rpc_methods.merge(backup_methods)?;

        Ok(rpc_methods)
    }

    async fn create_da_service(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        _require_wallet_check: bool,
        _task_manager: TaskExecutor,
    ) -> Result<Arc<Self::DaService>, anyhow::Error> {
        Ok(Arc::new(MockDaService::new(
            rollup_config.da.sender_address.clone(),
            &rollup_config.da.db_path,
        )))
    }

    fn create_da_verifier(&self) -> Self::DaVerifier {
        Default::default()
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
        da_service: &Arc<Self::DaService>,
        ledger_db: LedgerDB,
        proof_sampling_number: usize,
        is_light_client_prover: bool,
    ) -> ParallelProverService<Self::DaService, Self::Vm> {
        let vm = Risc0BonsaiHost::new(ledger_db.clone(), self.network);

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
