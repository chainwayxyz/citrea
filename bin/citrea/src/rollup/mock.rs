use async_trait::async_trait;
use citrea_prover::prover_service::ParallelProverService;
use citrea_risc0_bonsai_adapter::host::Risc0BonsaiHost;
use citrea_risc0_bonsai_adapter::Digest;
use citrea_stf::genesis_config::StorageConfig;
use citrea_stf::runtime::Runtime;
use sov_db::ledger_db::LedgerDB;
use sov_mock_da::{MockDaConfig, MockDaService, MockDaSpec};
use sov_modules_api::default_context::{DefaultContext, ZkDefaultContext};
use sov_modules_api::{Address, Spec};
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::zk::{Zkvm, ZkvmHost};
use sov_state::{DefaultStorageSpec, Storage, ZkStorage};
use sov_stf_runner::{FullNodeConfig, ProverConfig};

use crate::CitreaRollupBlueprint;

/// Rollup with MockDa
pub struct MockDemoRollup {}

impl CitreaRollupBlueprint for MockDemoRollup {}

#[async_trait]
impl RollupBlueprint for MockDemoRollup {
    type DaService = MockDaService;
    type DaSpec = MockDaSpec;
    type DaConfig = MockDaConfig;
    type Vm = Risc0BonsaiHost<'static>;

    type ZkContext = ZkDefaultContext;
    type NativeContext = DefaultContext;

    type StorageManager = ProverStorageManager<MockDaSpec, DefaultStorageSpec>;

    type ZkRuntime = Runtime<Self::ZkContext, Self::DaSpec>;
    type NativeRuntime = Runtime<Self::NativeContext, Self::DaSpec>;

    type ProverService = ParallelProverService<
        <<Self::NativeContext as Spec>::Storage as Storage>::Root,
        <<Self::NativeContext as Spec>::Storage as Storage>::Witness,
        Self::DaService,
        Self::Vm,
        StfBlueprint<Self::ZkContext, Self::DaSpec, <Self::Vm as ZkvmHost>::Guest, Self::ZkRuntime>,
    >;

    fn new() -> Self {
        Self {}
    }

    fn create_rpc_methods(
        &self,
        storage: &<Self::NativeContext as Spec>::Storage,
        ledger_db: &LedgerDB,
        da_service: &Self::DaService,
        sequencer_client_url: Option<String>,
    ) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error> {
        // TODO set the sequencer address
        let sequencer = Address::new([0; 32]);

        #[allow(unused_mut)]
        let mut rpc_methods = sov_modules_rollup_blueprint::register_rpc::<
            Self::NativeRuntime,
            Self::NativeContext,
            Self::DaService,
        >(storage, ledger_db, da_service, sequencer)?;

        crate::eth::register_ethereum::<Self::DaService>(
            da_service.clone(),
            storage.clone(),
            &mut rpc_methods,
            sequencer_client_url,
        )?;

        Ok(rpc_methods)
    }

    fn get_code_commitment(&self) -> <Self::Vm as Zkvm>::CodeCommitment {
        Digest::new(citrea_risc0::MOCK_DA_ID)
    }

    async fn create_da_service(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
    ) -> Self::DaService {
        MockDaService::new(rollup_config.da.sender_address, &rollup_config.da.db_path)
    }

    async fn create_prover_service(
        &self,
        prover_config: ProverConfig,
        _rollup_config: &FullNodeConfig<Self::DaConfig>,
        _da_service: &Self::DaService,
    ) -> Self::ProverService {
        let vm = Risc0BonsaiHost::new(
            citrea_risc0::MOCK_DA_ELF,
            std::env::var("BONSAI_API_URL").unwrap_or("".to_string()),
            std::env::var("BONSAI_API_KEY").unwrap_or("".to_string()),
        );
        let zk_stf = StfBlueprint::new();
        let zk_storage = ZkStorage::new();
        let da_verifier = Default::default();

        ParallelProverService::new_with_default_workers(
            vm,
            zk_stf,
            da_verifier,
            prover_config,
            zk_storage,
        )
        .expect("Should be able to instantiate prover service")
    }

    fn create_storage_manager(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
    ) -> anyhow::Result<Self::StorageManager> {
        let storage_config = StorageConfig {
            path: rollup_config.storage.path.clone(),
        };
        ProverStorageManager::new(storage_config)
    }
}
