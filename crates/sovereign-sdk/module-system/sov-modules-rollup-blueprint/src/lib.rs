#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

mod runtime_rpc;
mod wallet;
use std::net::SocketAddr;

use async_trait::async_trait;
use citrea_sequencer::{CitreaSequencer, SequencerConfig};
pub use runtime_rpc::*;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::{Context, DaSpec, Spec};
use sov_modules_stf_blueprint::{GenesisParams, Runtime as RuntimeTrait, StfBlueprint};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::{Zkvm, ZkvmHost};
use sov_state::storage::NativeStorage;
use sov_state::Storage;
use sov_stf_runner::{
    InitVariant, ProverConfig, ProverService, RollupConfig, StateTransitionRunner,
};
use tokio::sync::oneshot;
use tracing::instrument;
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
    type Vm: ZkvmHost + Zkvm + Send;

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

    /// Prover service.
    type ProverService: ProverService<
        Self::Vm,
        StateRoot = <<Self::NativeContext as Spec>::Storage as Storage>::Root,
        Witness = <<Self::NativeContext as Spec>::Storage as Storage>::Witness,
        DaService = Self::DaService,
    >;

    /// Creates a new instance of the blueprint.
    fn new() -> Self;

    /// Get code commitment.
    fn get_code_commitment(&self) -> <Self::Vm as Zkvm>::CodeCommitment;

    /// Creates RPC methods for the rollup.
    fn create_rpc_methods(
        &self,
        storage: &<Self::NativeContext as Spec>::Storage,
        ledger_db: &LedgerDB,
        da_service: &Self::DaService,
        sequencer_client_url: Option<String>,
    ) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error>;

    /// Creates GenesisConfig from genesis files.
    #[allow(clippy::type_complexity)]
    fn create_genesis_config(
        &self,
        rt_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        _rollup_config: &RollupConfig<Self::DaConfig>,
    ) -> anyhow::Result<
        GenesisParams<
            <Self::NativeRuntime as RuntimeTrait<Self::NativeContext, Self::DaSpec>>::GenesisConfig,
        >,
    > {
        let rt_genesis = <Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::genesis_config(rt_genesis_paths)?;

        Ok(GenesisParams {
            runtime: rt_genesis,
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
        prover_config: ProverConfig,
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
    #[instrument(level = "trace", skip_all)]
    async fn create_new_sequencer(
        &self,
        runtime_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
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
        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        let prev_root = ledger_db
            .get_head_soft_batch()?
            .map(|(number, _)| prover_storage.get_root_hash(number.0 + 1))
            .transpose()?;

        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods =
            self.create_rpc_methods(&prover_storage, &ledger_db, &da_service, None)?;

        let native_stf = StfBlueprint::new();

        let genesis_root = prover_storage.get_root_hash(1);

        let init_variant = match prev_root {
            Some(root_hash) => InitVariant::Initialized(root_hash),
            None => match genesis_root {
                Ok(root_hash) => InitVariant::Initialized(root_hash),
                _ => InitVariant::Genesis(genesis_config),
            },
        };

        let seq = CitreaSequencer::new(
            da_service,
            prover_storage,
            sequencer_config,
            native_stf,
            storage_manager,
            init_variant,
            rollup_config.public_keys,
            ledger_db,
            rollup_config.rpc,
        )
        .unwrap();

        Ok(Sequencer {
            runner: seq,
            rpc_methods,
        })
    }

    /// Creates a new prover
    #[instrument(level = "trace", skip_all)]
    async fn create_new_prover(
        &self,
        runtime_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        rollup_config: RollupConfig<Self::DaConfig>,
        prover_config: ProverConfig,
    ) -> Result<Prover<Self>, anyhow::Error>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let da_service = self.create_da_service(&rollup_config).await;

        let prover_service = self
            .create_prover_service(prover_config.clone(), &rollup_config, &da_service)
            .await;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let ledger_db = self.create_ledger_db(&rollup_config);
        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        let prev_root = ledger_db
            .get_head_soft_batch()?
            .map(|(number, _)| prover_storage.get_root_hash(number.0 + 1))
            .transpose()?;

        let runner_config = rollup_config.runner.expect("Runner config is missing");
        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods = self.create_rpc_methods(
            &prover_storage,
            &ledger_db,
            &da_service,
            Some(runner_config.sequencer_client_url.clone()),
        )?;

        let native_stf = StfBlueprint::new();

        let genesis_root = prover_storage.get_root_hash(1);

        let init_variant = match prev_root {
            Some(root_hash) => InitVariant::Initialized(root_hash),
            None => match genesis_root {
                Ok(root_hash) => InitVariant::Initialized(root_hash),
                _ => InitVariant::Genesis(genesis_config),
            },
        };

        let code_commitment = self.get_code_commitment();

        let runner = StateTransitionRunner::new(
            runner_config,
            rollup_config.public_keys,
            rollup_config.rpc,
            rollup_config.utility_server,
            da_service,
            ledger_db,
            native_stf,
            storage_manager,
            init_variant,
            Some(prover_service),
            Some(prover_config),
            code_commitment,
        )?;

        Ok(Prover {
            runner,
            rpc_methods,
        })
    }

    /// Creates a new rollup.
    #[instrument(level = "trace", skip_all)]
    async fn create_new_rollup(
        &self,
        runtime_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        rollup_config: RollupConfig<Self::DaConfig>,
    ) -> Result<FullNode<Self>, anyhow::Error>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let da_service = self.create_da_service(&rollup_config).await;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let ledger_db = self.create_ledger_db(&rollup_config);
        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        let prev_root = ledger_db
            .get_head_soft_batch()?
            .map(|(number, _)| prover_storage.get_root_hash(number.0 + 1))
            .transpose()?;

        let runner_config = rollup_config.runner.expect("Runner config is missing");
        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods = self.create_rpc_methods(
            &prover_storage,
            &ledger_db,
            &da_service,
            Some(runner_config.sequencer_client_url.clone()),
        )?;

        let native_stf = StfBlueprint::new();

        let genesis_root = prover_storage.get_root_hash(1);

        let init_variant = match prev_root {
            Some(root_hash) => InitVariant::Initialized(root_hash),
            None => match genesis_root {
                Ok(root_hash) => InitVariant::Initialized(root_hash),
                _ => InitVariant::Genesis(genesis_config),
            },
        };

        let code_commitment = self.get_code_commitment();

        let runner = StateTransitionRunner::new(
            runner_config,
            rollup_config.public_keys,
            rollup_config.rpc,
            rollup_config.utility_server,
            da_service,
            ledger_db,
            native_stf,
            storage_manager,
            init_variant,
            None,
            None,
            code_commitment,
        )?;

        Ok(FullNode {
            runner,
            rpc_methods,
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
        StfBlueprint<S::NativeContext, S::DaSpec, S::Vm, S::NativeRuntime>,
    >,
    /// Rpc methods for the rollup.
    pub rpc_methods: jsonrpsee::RpcModule<()>,
}

impl<S: RollupBlueprint> Sequencer<S> {
    /// Runs the sequencer.
    #[instrument(level = "trace", skip_all, err, ret(level = "error"))]
    pub async fn run(self) -> Result<(), anyhow::Error> {
        self.run_and_report_ports(None, None).await
    }

    /// Runs the sequencer.
    pub async fn run_and_report_rpc_port(
        self,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        let mut seq = self.runner;
        seq.start_rpc_server(channel, self.rpc_methods)
            .await
            .unwrap();
        seq.run().await?;
        Ok(())
    }

    /// Runs the sequencer and reports rpc and utility server ports.
    pub async fn run_and_report_ports(
        self,
        rpc_channel: Option<oneshot::Sender<SocketAddr>>,
        utility_channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        let mut seq = self.runner;
        seq.start_rpc_server(rpc_channel, self.rpc_methods)
            .await
            .unwrap();
        seq.start_utility_server(utility_channel).await.unwrap();
        seq.run().await?;
        Ok(())
    }
}

/// Dependencies needed to run the rollup.
pub struct FullNode<S: RollupBlueprint> {
    /// The State Transition Runner.
    #[allow(clippy::type_complexity)]
    pub runner: StateTransitionRunner<
        StfBlueprint<S::NativeContext, S::DaSpec, S::Vm, S::NativeRuntime>,
        S::StorageManager,
        S::DaService,
        S::Vm,
        S::ProverService,
        S::NativeContext,
    >,
    /// Rpc methods for the rollup.
    pub rpc_methods: jsonrpsee::RpcModule<()>,
}

impl<S: RollupBlueprint> FullNode<S> {
    /// Runs the rollup.
    #[instrument(level = "trace", skip(self), err, ret(level = "error"))]
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

        runner.run_in_process().await?;
        Ok(())
    }

    /// Runs the rollup. Reports rpc and utility server port to the caller using the provided channel.
    pub async fn run_and_report_ports(
        self,
        rpc_channel: Option<oneshot::Sender<SocketAddr>>,
        utility_channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        let mut runner = self.runner;
        runner.start_rpc_server(self.rpc_methods, rpc_channel).await;
        runner.start_utility_server(utility_channel).await;

        runner.run_prover_process().await?;
        Ok(())
    }
}

/// Dependencies needed to run the rollup.
pub struct Prover<S: RollupBlueprint> {
    /// The State Transition Runner.
    #[allow(clippy::type_complexity)]
    pub runner: StateTransitionRunner<
        StfBlueprint<S::NativeContext, S::DaSpec, S::Vm, S::NativeRuntime>,
        S::StorageManager,
        S::DaService,
        S::Vm,
        S::ProverService,
        S::NativeContext,
    >,
    /// Rpc methods for the rollup.
    pub rpc_methods: jsonrpsee::RpcModule<()>,
}

impl<S: RollupBlueprint> Prover<S> {
    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err, ret(level = "error"))]
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

        runner.run_prover_process().await?;
        Ok(())
    }

    /// Runs the rollup. Reports rpc and utility server port to the caller using the provided channel.
    pub async fn run_and_report_ports(
        self,
        rpc_channel: Option<oneshot::Sender<SocketAddr>>,
        utility_channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        let mut runner = self.runner;
        runner.start_rpc_server(self.rpc_methods, rpc_channel).await;
        runner.start_utility_server(utility_channel).await;

        runner.run_prover_process().await?;
        Ok(())
    }
}
