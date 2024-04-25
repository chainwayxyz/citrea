#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

mod runtime_rpc;
mod wallet;
use std::net::SocketAddr;

use async_trait::async_trait;
use citrea_sequencer::{CitreaSequencer, SequencerConfig};
use const_rollup_config::TEST_PRIVATE_KEY;
pub use runtime_rpc::*;
use sequencer_client::SequencerClient;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::runtime::capabilities::{Kernel, KernelSlotHooks};
use sov_modules_api::{Context, DaSpec, Spec};
use sov_modules_stf_blueprint::{GenesisParams, Runtime as RuntimeTrait, StfBlueprint};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::ZkvmHost;
use sov_state::storage::NativeStorage;
use sov_state::Storage;
use sov_stf_runner::{
    InitVariant, ProverService, RollupConfig, RollupProverConfig, StateTransitionRunner,
};
use tokio::sync::{oneshot, watch};
pub use wallet::*;

/// This trait defines how to crate all the necessary dependencies required by a rollup.
#[async_trait]
pub trait RollupBlueprint: Sized + Send + Sync {
    /// Data Availability service.
    type DaService: DaService<Spec = Self::DaSpec, Error = anyhow::Error> + Clone + Send + Sync;
    /// A specification for the types used by a DA layer.
    type DaSpec: DaSpec + Send + Sync;
    /// Data Availability config.
    type DaConfig: Send + Sync;

    /// Host of a zkVM program.
    type Vm: ZkvmHost + Send;

    /// Context for Zero Knowledge environment.
    type ZkContext: Context;
    /// Context for Native environment.
    type NativeContext: Context;

    /// Manager for the native storage lifecycle.
    type StorageManager: HierarchicalStorageManager<
        Self::DaSpec,
        NativeStorage = <Self::NativeContext as Spec>::Storage,
        NativeChangeSet = <Self::NativeContext as Spec>::Storage,
    >;

    /// Runtime for the Zero Knowledge environment.
    type ZkRuntime: RuntimeTrait<Self::ZkContext, Self::DaSpec> + Default;
    /// Runtime for the Native environment.
    type NativeRuntime: RuntimeTrait<Self::NativeContext, Self::DaSpec> + Default + Send + Sync;

    /// The kernel for the native environment.
    type NativeKernel: KernelSlotHooks<Self::NativeContext, Self::DaSpec> + Default + Send + Sync;
    /// The kernel for the Zero Knowledge environment.
    type ZkKernel: KernelSlotHooks<Self::ZkContext, Self::DaSpec> + Default;

    /// Prover service.
    type ProverService: ProverService<
        StateRoot = <<Self::NativeContext as Spec>::Storage as Storage>::Root,
        Witness = <<Self::NativeContext as Spec>::Storage as Storage>::Witness,
        DaService = Self::DaService,
    >;

    /// Creates a new instance of the blueprint.
    fn new() -> Self;

    /// Creates RPC methods for the rollup.
    fn create_rpc_methods(
        &self,
        storage: watch::Receiver<<Self::NativeContext as Spec>::Storage>,
        ledger_db: &LedgerDB,
        da_service: &Self::DaService,
        sequencer_client: Option<SequencerClient>,
    ) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error>;

    /// Creates GenesisConfig from genesis files.
    #[allow(clippy::type_complexity)]
    fn create_genesis_config(
        &self,
        rt_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        kernel_genesis: <Self::NativeKernel as Kernel<Self::NativeContext, Self::DaSpec>>::GenesisConfig,
        _rollup_config: &RollupConfig<Self::DaConfig>,
    ) -> anyhow::Result<
        GenesisParams<
            <Self::NativeRuntime as RuntimeTrait<Self::NativeContext, Self::DaSpec>>::GenesisConfig,
            <Self::NativeKernel as Kernel<Self::NativeContext, Self::DaSpec>>::GenesisConfig,
        >,
    > {
        let rt_genesis = <Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::genesis_config(rt_genesis_paths)?;

        Ok(GenesisParams {
            runtime: rt_genesis,
            kernel: kernel_genesis,
        })
    }

    /// Creates instance of [`DaService`].
    async fn create_da_service(
        &self,
        rollup_config: &RollupConfig<Self::DaConfig>,
    ) -> Self::DaService;

    /// Creates instance of [`ProverService`].
    async fn create_prover_service(
        &self,
        prover_config: RollupProverConfig,
        rollup_config: &RollupConfig<Self::DaConfig>,
        da_service: &Self::DaService,
    ) -> Self::ProverService;

    /// Creates instance of [`Self::StorageManager`].
    /// Panics if initialization fails.
    fn create_storage_manager(
        &self,
        rollup_config: &RollupConfig<Self::DaConfig>,
    ) -> Result<Self::StorageManager, anyhow::Error>;

    /// Creates instance of a LedgerDB.
    fn create_ledger_db(&self, rollup_config: &RollupConfig<Self::DaConfig>) -> LedgerDB {
        LedgerDB::with_path(&rollup_config.storage.path).expect("Ledger DB failed to open")
    }

    /// Creates a new sequencer
    async fn create_new_sequencer(
        &self,
        runtime_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        kernel_genesis_config: <Self::NativeKernel as Kernel<Self::NativeContext, Self::DaSpec>>::GenesisConfig,
        rollup_config: RollupConfig<Self::DaConfig>,
        sequencer_config: SequencerConfig,
    ) -> Result<Sequencer<Self>, anyhow::Error>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let da_service = self.create_da_service(&rollup_config).await;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let ledger_db = self.create_ledger_db(&rollup_config);
        let genesis_config = self.create_genesis_config(
            runtime_genesis_paths,
            kernel_genesis_config,
            &rollup_config,
        )?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        let prev_root = ledger_db
            .get_head_soft_batch()?
            .map(|(number, _)| prover_storage.get_root_hash(number.0 + 1))
            .transpose()?;

        let genesis_root = prover_storage.get_root_hash(1);

        let init_variant = match prev_root {
            Some(root_hash) => InitVariant::Initialized(root_hash),
            None => match genesis_root {
                Ok(root_hash) => InitVariant::Initialized(root_hash),
                _ => InitVariant::Genesis(genesis_config),
            },
        };

        // TODO: Decide what to do with this.
        let prover_storage_c = prover_storage.clone();

        let rpc_storage = watch::channel(prover_storage);
        // We pass "bootstrap" storage here,
        // as it will be replaced with the latest on after first processed block.
        let rpc_methods =
            self.create_rpc_methods(rpc_storage.1.clone(), &ledger_db, &da_service, None)?;

        let native_stf = StfBlueprint::new();

        let seq =
            CitreaSequencer::new(
                da_service,
                <<<Self as RollupBlueprint>::NativeContext as Spec>::PrivateKey as TryFrom<
                    &[u8],
                >>::try_from(hex::decode(TEST_PRIVATE_KEY).unwrap().as_slice())
                .unwrap(),
                prover_storage_c,
                rpc_storage.0,
                sequencer_config,
                native_stf,
                storage_manager,
                init_variant,
                rollup_config.sequencer_public_key,
                ledger_db,
                rollup_config.runner,
            )
            .unwrap();

        Ok(Sequencer {
            runner: seq,
            rpc_methods,
            storage: rpc_storage.1,
        })
    }

    /// Creates a new rollup.
    async fn create_new_rollup(
        &self,
        runtime_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        kernel_genesis_config: <Self::NativeKernel as Kernel<Self::NativeContext, Self::DaSpec>>::GenesisConfig,
        rollup_config: RollupConfig<Self::DaConfig>,
        prover_config: RollupProverConfig,
        is_prover: bool,
    ) -> Result<Rollup<Self>, anyhow::Error>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let da_service = self.create_da_service(&rollup_config).await;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let prover_service = match is_prover {
            true => Some(
                self.create_prover_service(prover_config, &rollup_config, &da_service)
                    .await,
            ),
            false => None,
        };

        let genesis_config = self.create_genesis_config(
            runtime_genesis_paths,
            kernel_genesis_config,
            &rollup_config,
        )?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;
        let ledger_db = self.create_ledger_db(&rollup_config);

        let prev_root = ledger_db
            .get_head_soft_batch()?
            .map(|(number, _)| prover_storage.get_root_hash(number.0 + 1))
            .transpose()?;

        // if node does not have a sequencer client, then it is a sequencer
        let sequencer_client = rollup_config
            .sequencer_client
            .map(|s| SequencerClient::new(s.url));

        let genesis_root = prover_storage.get_root_hash(1);

        let init_variant = match prev_root {
            Some(root_hash) => InitVariant::Initialized(root_hash),
            None => match genesis_root {
                Ok(root_hash) => InitVariant::Initialized(root_hash),
                _ => InitVariant::Genesis(genesis_config),
            },
        };

        let rpc_storage = watch::channel(prover_storage);
        // We pass "bootstrap" storage here,
        // as it will be replaced with the latest on after first processed block.
        let rpc_methods = self.create_rpc_methods(
            rpc_storage.1,
            &ledger_db,
            &da_service,
            sequencer_client.clone(),
        )?;

        let native_stf = StfBlueprint::new();

        let runner = StateTransitionRunner::new(
            rollup_config.runner,
            da_service,
            ledger_db,
            native_stf,
            storage_manager,
            rpc_storage.0,
            init_variant,
            prover_service,
            sequencer_client,
            rollup_config.sequencer_public_key,
            rollup_config.sequencer_da_pub_key,
            rollup_config.prover_da_pub_key,
            rollup_config.include_tx_body,
        )?;

        Ok(Rollup {
            runner,
            rpc_methods,
            is_prover,
        })
    }
}

/// Sequencer stf runner
pub struct Sequencer<S: RollupBlueprint> {
    /// The State Transition Runner of Sequencer.
    #[allow(clippy::type_complexity)]
    pub runner: CitreaSequencer<
        S::NativeContext,
        S::DaService,
        S::StorageManager,
        S::Vm,
        StfBlueprint<S::NativeContext, S::DaSpec, S::Vm, S::NativeRuntime, S::NativeKernel>,
    >,
    /// Rpc methods for the rollup.
    pub rpc_methods: jsonrpsee::RpcModule<()>,
    storage: watch::Receiver<<S::NativeContext as Spec>::Storage>,
}

impl<S: RollupBlueprint> Sequencer<S> {
    /// Runs the sequencer.
    pub async fn run(self) -> Result<(), anyhow::Error> {
        self.run_and_report_rpc_port(None).await
    }

    /// Runs the sequencer.
    pub async fn run_and_report_rpc_port(
        self,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        let mut seq = self.runner;
        seq.start_rpc_server(channel, self.rpc_methods, self.storage)
            .await
            .unwrap();
        seq.run().await?;
        Ok(())
    }
}

/// Dependencies needed to run the rollup.
pub struct Rollup<S: RollupBlueprint> {
    /// The State Transition Runner.
    #[allow(clippy::type_complexity)]
    pub runner: StateTransitionRunner<
        StfBlueprint<S::NativeContext, S::DaSpec, S::Vm, S::NativeRuntime, S::NativeKernel>,
        S::StorageManager,
        S::DaService,
        S::Vm,
        S::ProverService,
        S::NativeContext,
    >,
    /// Rpc methods for the rollup.
    pub rpc_methods: jsonrpsee::RpcModule<()>,
    /// True for prover node, false for full node.
    pub is_prover: bool,
}

impl<S: RollupBlueprint> Rollup<S> {
    /// Runs the rollup.
    pub async fn run(self) -> Result<(), anyhow::Error> {
        self.run_and_report_rpc_port(None).await
    }

    /// Only run the rpc.
    pub async fn run_rpc(self) -> Result<(), anyhow::Error> {
        self.runner.start_rpc_server(self.rpc_methods, None).await;
        Ok(())
    }

    /// Runs the rollup. Reports rpc port to the caller using the provided channel.
    pub async fn run_and_report_rpc_port(
        self,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        let mut runner = self.runner;
        runner.start_rpc_server(self.rpc_methods, channel).await;
        if self.is_prover {
            runner.run_prover_process().await?;
        } else {
            runner.run_in_process().await?;
        }
        Ok(())
    }
}
