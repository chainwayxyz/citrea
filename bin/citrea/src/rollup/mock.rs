use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use citrea_common::rpc::register_healthcheck_rpc;
use citrea_common::{FullNodeConfig, ProverConfig};
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
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::{Zkvm, ZkvmHost};
use sov_state::{DefaultStorageSpec, Storage, ZkStorage};
use tokio::sync::broadcast;

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
        da_service: &Arc<Self::DaService>,
        sequencer_client_url: Option<String>,
        soft_confirmation_rx: Option<broadcast::Receiver<u64>>,
    ) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error> {
        // TODO set the sequencer address
        let sequencer = Address::new([0; 32]);

        let mut rpc_methods = sov_modules_rollup_blueprint::register_rpc::<
            Self::NativeRuntime,
            Self::NativeContext,
            Self::DaService,
        >(storage, ledger_db, da_service, sequencer)?;

        crate::eth::register_ethereum::<Self::DaService>(
            da_service.clone(),
            storage.clone(),
            ledger_db.clone(),
            &mut rpc_methods,
            sequencer_client_url,
            soft_confirmation_rx,
        )?;

        register_healthcheck_rpc(&mut rpc_methods, ledger_db.clone())?;

        Ok(rpc_methods)
    }

    fn get_code_commitments_by_spec(&self) -> HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment> {
        let mut map = HashMap::new();
        map.insert(SpecId::Genesis, Digest::new(citrea_risc0::MOCK_DA_ID));
        map
    }

    async fn create_da_service(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        _require_wallet_check: bool,
    ) -> Result<Arc<Self::DaService>, anyhow::Error> {
        Ok(Arc::new(MockDaService::new(
            rollup_config.da.sender_address,
            &rollup_config.da.db_path,
        )))
    }

    // async fn create_prover_service(
    //     &self,
    //     prover_config: ProverConfig,
    //     _rollup_config: &FullNodeConfig<Self::DaConfig>,
    //     _da_service: &Arc<Self::DaService>,
    //     ledger_db: LedgerDB,
    // ) -> Self::ProverService {
    //     let private_key_str = env::var("private_key").context("private_key not set")?;
    //     let rpc_url_str = env::var("RPC_URL").context("RPC_URL not set")?;
    //     let proof_market_address_str =
    //         env::var("PROOF_MARKET_ADDRESS").context("PROOF_MARKET_ADDRESS not set")?;
    //     let set_verifier_address_str =
    //         env::var("SET_VERIFIER_ADDRESS").context("SET_VERIFIER_ADDRESS not set")?;
    //     // ALSO SET THESE ENV VARIABLES
    //     // PINATA_JWT
    //     // PINATA_API_URL
    //     // IPFS_GATEWAY_URL
    //     let vm = Risc0BoundlessHost::new(
    //         citrea_risc0::MOCK_DA_ELF,
    //         ledger_db.clone(),
    //         private_key_str,
    //         Url::parse(rpc_url_str).unwrap(),
    //         proof_market_address_str,
    //         set_verifier_address_str,
    //     )
    //     .await;
    //     let zk_stf = StfBlueprint::new();
    //     let zk_storage = ZkStorage::new();

    //     let da_verifier = Default::default();
    //     ParallelProverService::new_with_default_workers(
    //         vm,
    //         zk_stf,
    //         da_verifier,
    //         prover_config,
    //         zk_storage,
    //         ledger_db,
    //     )
    //     .expect("Should be able to instantiate prover service")
    // }

    async fn create_prover_service(
        &self,
        prover_config: ProverConfig,
        _rollup_config: &FullNodeConfig<Self::DaConfig>,
        _da_service: &Arc<Self::DaService>,
        ledger_db: LedgerDB,
    ) -> Self::ProverService {
        let vm = Risc0BonsaiHost::new(
            citrea_risc0::MOCK_DA_ELF,
            std::env::var("BONSAI_API_URL").unwrap_or("".to_string()),
            std::env::var("BONSAI_API_KEY").unwrap_or("".to_string()),
            ledger_db.clone(),
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
            ledger_db,
        )
        .expect("Should be able to instantiate prover service")
    }

    fn create_storage_manager(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
    ) -> anyhow::Result<Self::StorageManager> {
        let storage_config = StorageConfig {
            path: rollup_config.storage.path.clone(),
            db_max_open_files: rollup_config.storage.db_max_open_files,
        };
        ProverStorageManager::new(storage_config)
    }
}
