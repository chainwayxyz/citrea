use async_trait::async_trait;
use bitcoin_da::service::{BitcoinService, DaServiceConfig};
use bitcoin_da::spec::{BitcoinSpec, RollupParams};
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_stf::genesis_config::StorageConfig;
use citrea_stf::runtime::Runtime;
use rollup_constants::{DA_TX_ID_LEADING_ZEROS, ROLLUP_NAME};
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::{DefaultContext, ZkDefaultContext};
use sov_modules_api::{Address, Spec};
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_risc0_adapter::host::Risc0Host;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::zk::ZkvmHost;
use sov_state::{DefaultStorageSpec, Storage, ZkStorage};
use sov_stf_runner::{ParallelProverService, ProverConfig, RollupConfig};

/// Rollup with BitcoinDa
pub struct BitcoinRollup {}

#[async_trait]
impl RollupBlueprint for BitcoinRollup {
    type DaService = BitcoinService;
    type DaSpec = BitcoinSpec;
    type DaConfig = DaServiceConfig;
    type Vm = Risc0Host<'static>;

    type ZkContext = ZkDefaultContext;
    type NativeContext = DefaultContext;

    type StorageManager = ProverStorageManager<BitcoinSpec, DefaultStorageSpec>;

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
        // unused inside register RPC
        let sov_sequencer = Address::new([0; 32]);

        #[allow(unused_mut)]
        let mut rpc_methods = sov_modules_rollup_blueprint::register_rpc::<
            Self::NativeRuntime,
            Self::NativeContext,
            Self::DaService,
        >(storage, ledger_db, da_service, sov_sequencer)?;

        crate::eth::register_ethereum::<Self::DaService>(
            da_service.clone(),
            storage.clone(),
            &mut rpc_methods,
            sequencer_client_url,
        )?;

        Ok(rpc_methods)
    }

    fn create_storage_manager(
        &self,
        rollup_config: &sov_stf_runner::RollupConfig<Self::DaConfig>,
    ) -> Result<Self::StorageManager, anyhow::Error> {
        let storage_config = StorageConfig {
            path: rollup_config.storage.path.clone(),
        };
        ProverStorageManager::new(storage_config)
    }

    async fn create_da_service(
        &self,
        rollup_config: &RollupConfig<Self::DaConfig>,
    ) -> Self::DaService {
        BitcoinService::new(
            rollup_config.da.clone(),
            RollupParams {
                rollup_name: ROLLUP_NAME.to_string(),
                reveal_tx_id_prefix: DA_TX_ID_LEADING_ZEROS.to_vec(),
            },
        )
        .await
    }

    async fn create_prover_service(
        &self,
        prover_config: ProverConfig,
        _rollup_config: &RollupConfig<Self::DaConfig>,
        _da_service: &Self::DaService,
    ) -> Self::ProverService {
        // TODO: will be BITCOIN_ELF
        let vm = Risc0Host::new(risc0::MOCK_DA_ELF);
        let zk_stf = StfBlueprint::new();
        let zk_storage = ZkStorage::new();

        let da_verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: ROLLUP_NAME.to_string(),
            reveal_tx_id_prefix: DA_TX_ID_LEADING_ZEROS.to_vec(),
        });

        ParallelProverService::new_with_default_workers(
            vm,
            zk_stf,
            da_verifier,
            prover_config,
            zk_storage,
        )
        .expect("Should be able to instantiate prover service")
    }
}
