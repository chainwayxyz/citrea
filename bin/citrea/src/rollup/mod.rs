use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use citrea_batch_prover::da_block_handler::L1BlockHandler as BatchProverL1BlockHandler;
use citrea_batch_prover::CitreaBatchProver;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::{BatchProverConfig, FullNodeConfig, LightClientProverConfig, SequencerConfig};
use citrea_fullnode::da_block_handler::L1BlockHandler as FullNodeL1BlockHandler;
use citrea_fullnode::CitreaFullnode;
use citrea_light_client_prover::da_block_handler::L1BlockHandler as LightClientProverL1BlockHandler;
use citrea_light_client_prover::runner::CitreaLightClientProver;
use citrea_primitives::forks::get_forks;
use citrea_sequencer::CitreaSequencer;
use citrea_storage_ops::pruning::PrunerService;
use jsonrpsee::RpcModule;
use sov_db::ledger_db::migrations::{LedgerDBMigrator, Migrations};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::types::SoftConfirmationNumber;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::{
    GenesisParams as StfGenesisParams, Runtime as RuntimeTrait, StfBlueprint,
};
use sov_prover_storage_manager::{ProverStorageManager, SnapshotManager};
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_state::storage::NativeStorage;
use sov_state::{ArrayWitness, ProverStorage};
use sov_stf_runner::InitParams;
use tokio::sync::broadcast;
use tracing::{debug, info, instrument};

mod bitcoin;
mod mock;
pub use bitcoin::*;
pub use mock::*;

type GenesisParams<T> = StfGenesisParams<
    <<T as RollupBlueprint>::NativeRuntime as RuntimeTrait<
        <T as RollupBlueprint>::NativeContext,
        <T as RollupBlueprint>::DaSpec,
    >>::GenesisConfig,
>;

/// Group for storage instances
pub struct Storage<T: RollupBlueprint> {
    /// The ledger DB instance
    pub ledger_db: LedgerDB,
    /// The prover storage manager instance.
    pub storage_manager: ProverStorageManager<<T as RollupBlueprint>::DaSpec>,
    /// The prover storage
    pub prover_storage: ProverStorage<SnapshotManager>,
}

/// Group for initialization dependencies
pub struct Dependencies<T: RollupBlueprint> {
    /// The task manager
    pub task_manager: TaskManager<()>,
    /// The DA service
    pub da_service: Arc<<T as RollupBlueprint>::DaService>,
    /// The channel on which L2 block number is broadcasted.
    pub soft_confirmation_channel: (broadcast::Sender<u64>, Option<broadcast::Receiver<u64>>),
}

/// Overrides RollupBlueprint methods
#[async_trait]
pub trait CitreaRollupBlueprint: RollupBlueprint {
    /// Setup the rollup's dependencies
    async fn setup_dependencies(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        require_da_wallet: bool,
    ) -> Result<Dependencies<Self>> {
        let mut task_manager = TaskManager::default();
        let da_service = self
            .create_da_service(rollup_config, require_da_wallet, &mut task_manager)
            .await?;
        let (soft_confirmation_tx, soft_confirmation_rx) = broadcast::channel(10);
        // If subscriptions disabled, pass None
        let soft_confirmation_rx = if rollup_config.rpc.enable_subscriptions {
            Some(soft_confirmation_rx)
        } else {
            None
        };

        Ok(Dependencies {
            task_manager,
            da_service,
            soft_confirmation_channel: (soft_confirmation_tx, soft_confirmation_rx),
        })
    }

    /// Setup the rollup's storage access
    fn setup_storage(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        rocksdb_config: &RocksdbConfig,
    ) -> Result<Storage<Self>> {
        let ledger_db = self.create_ledger_db(rocksdb_config);
        let mut storage_manager = self.create_storage_manager(rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        Ok(Storage {
            ledger_db,
            storage_manager,
            prover_storage,
        })
    }

    /// Setup the RPC server
    fn setup_rpc(
        &self,
        prover_storage: &ProverStorage<SnapshotManager>,
        ledger_db: LedgerDB,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        sequencer_client_url: Option<String>,
        soft_confirmation_rx: Option<broadcast::Receiver<u64>>,
    ) -> Result<RpcModule<()>> {
        self.create_rpc_methods(
            prover_storage,
            &ledger_db,
            &da_service,
            sequencer_client_url,
            soft_confirmation_rx,
        )
    }

    /// Creates a new sequencer
    #[instrument(level = "trace", skip_all)]
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn create_sequencer(
        &self,
        genesis_config: GenesisParams<Self>,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        sequencer_config: SequencerConfig,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        ledger_db: LedgerDB,
        mut storage_manager: ProverStorageManager<<Self as RollupBlueprint>::DaSpec>,
        prover_storage: ProverStorage<SnapshotManager>,
        soft_confirmation_tx: broadcast::Sender<u64>,
        rpc_module: RpcModule<()>,
    ) -> Result<(
        CitreaSequencer<Self::NativeContext, Self::DaService, LedgerDB, Self::NativeRuntime>,
        RpcModule<()>,
    )>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(SoftConfirmationNumber(0));

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let native_stf = StfBlueprint::new();
        let init_params = self.init_chain(
            genesis_config,
            &native_stf,
            &ledger_db,
            &mut storage_manager,
            &prover_storage,
        )?;

        citrea_sequencer::build_services(
            sequencer_config,
            init_params,
            native_stf,
            rollup_config.public_keys,
            da_service,
            ledger_db,
            storage_manager,
            prover_storage,
            soft_confirmation_tx,
            fork_manager,
            rpc_module,
        )
    }

    /// Creates a new rollup.
    #[instrument(level = "trace", skip_all)]
    #[allow(clippy::too_many_arguments)]
    async fn create_full_node(
        &self,
        genesis_config: GenesisParams<Self>,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        ledger_db: LedgerDB,
        mut storage_manager: ProverStorageManager<<Self as RollupBlueprint>::DaSpec>,
        prover_storage: ProverStorage<SnapshotManager>,
        soft_confirmation_tx: broadcast::Sender<u64>,
    ) -> Result<(
        CitreaFullnode<Self::DaService, Self::NativeContext, LedgerDB, Self::NativeRuntime>,
        FullNodeL1BlockHandler<Self::NativeContext, Self::Vm, Self::DaService, LedgerDB>,
        Option<PrunerService<LedgerDB>>,
    )>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let runner_config = rollup_config.runner.expect("Runner config is missing");

        let native_stf = StfBlueprint::new();
        let init_params = self.init_chain(
            genesis_config,
            &native_stf,
            &ledger_db,
            &mut storage_manager,
            &prover_storage,
        )?;

        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(SoftConfirmationNumber(0));

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let code_commitments = self.get_batch_proof_code_commitments();

        citrea_fullnode::build_services(
            runner_config,
            init_params,
            native_stf,
            rollup_config.public_keys,
            da_service,
            ledger_db,
            storage_manager,
            soft_confirmation_tx,
            fork_manager,
            code_commitments,
        )
    }

    /// Creates a new prover
    #[instrument(level = "trace", skip_all)]
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    async fn create_batch_prover(
        &self,
        prover_config: BatchProverConfig,
        genesis_config: GenesisParams<Self>,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        ledger_db: LedgerDB,
        mut storage_manager: ProverStorageManager<<Self as RollupBlueprint>::DaSpec>,
        prover_storage: ProverStorage<SnapshotManager>,
        soft_confirmation_tx: broadcast::Sender<u64>,
        rpc_module: RpcModule<()>,
    ) -> Result<(
        CitreaBatchProver<Self::NativeContext, Self::DaService, LedgerDB, Self::NativeRuntime>,
        BatchProverL1BlockHandler<
            Self::Vm,
            Self::DaService,
            Self::ProverService,
            LedgerDB,
            ArrayWitness,
            Transaction<<Self as RollupBlueprint>::NativeContext>,
        >,
        RpcModule<()>,
    )>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let runner_config = rollup_config.runner.expect("Runner config is missing");

        let native_stf = StfBlueprint::new();
        let init_params = self.init_chain(
            genesis_config,
            &native_stf,
            &ledger_db,
            &mut storage_manager,
            &prover_storage,
        )?;

        let current_l2_height = ledger_db
            .get_head_soft_confirmation_height()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .unwrap_or(0);

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let prover_service = Arc::new(
            self.create_prover_service(
                prover_config.proving_mode,
                &da_service,
                ledger_db.clone(),
                prover_config.proof_sampling_number,
                false,
            )
            .await,
        );
        let code_commitments = self.get_batch_proof_code_commitments();
        let elfs = self.get_batch_proof_elfs();

        citrea_batch_prover::build_services(
            prover_config,
            runner_config,
            init_params,
            native_stf,
            rollup_config.public_keys,
            da_service,
            prover_service,
            ledger_db,
            storage_manager,
            soft_confirmation_tx,
            fork_manager,
            code_commitments,
            elfs,
            rpc_module,
        )
        .await
    }

    /// Creates a new light client prover
    #[instrument(level = "trace", skip_all)]
    async fn create_light_client_prover(
        &self,
        prover_config: LightClientProverConfig,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        rocksdb_config: &RocksdbConfig,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        ledger_db: LedgerDB,
        rpc_module: RpcModule<()>,
    ) -> Result<(
        CitreaLightClientProver,
        LightClientProverL1BlockHandler<Self::Vm, Self::DaService, Self::ProverService, LedgerDB>,
        RpcModule<()>,
    )>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let runner_config = rollup_config.runner.expect("Runner config is missing");

        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(SoftConfirmationNumber(0));

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let prover_service = Arc::new(
            self.create_prover_service(
                prover_config.proving_mode,
                &da_service,
                ledger_db.clone(),
                prover_config.proof_sampling_number,
                true,
            )
            .await,
        );

        let batch_prover_code_commitments = self.get_batch_proof_code_commitments();
        let code_commitments = self.get_light_client_proof_code_commitments();
        let elfs = self.get_light_client_elfs();

        citrea_light_client_prover::build_services(
            prover_config,
            runner_config,
            rocksdb_config,
            ledger_db,
            da_service,
            prover_service,
            rollup_config.public_keys,
            batch_prover_code_commitments,
            code_commitments,
            elfs,
            rpc_module,
        )
    }

    /// Run Ledger DB migrations
    fn run_ledger_migrations(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        tables: Vec<String>,
        migrations: Migrations,
    ) -> anyhow::Result<()> {
        // Migrate before constructing ledger_db instance so that no lock is present.
        let migrator = LedgerDBMigrator::new(rollup_config.storage.path.as_path(), migrations);
        migrator.migrate(rollup_config.storage.db_max_open_files, tables)?;
        Ok(())
    }

    /// Initialize the chain from existing data, if any.
    /// Otherwise, fallback to initialization from genesis
    #[allow(clippy::type_complexity)]
    fn init_chain(
        &self,
        genesis_config: GenesisParams<Self>,
        stf: &StfBlueprint<Self::NativeContext, Self::DaSpec, Self::NativeRuntime>,
        ledger_db: &LedgerDB,
        storage_manager: &mut ProverStorageManager<Self::DaSpec>,
        prover_storage: &ProverStorage<SnapshotManager>,
    ) -> anyhow::Result<InitParams> {
        if let Some((number, soft_confirmation)) = ledger_db.get_head_soft_confirmation()? {
            // At least one soft confirmation was processed
            info!("Initialize node at L2 height #{}. State root: 0x{}. Last soft confirmation hash: 0x{}.", number.0, hex::encode(prover_storage.get_root_hash(number.0 + 1)?), hex::encode(soft_confirmation.hash));

            return Ok(InitParams {
                state_root: prover_storage.get_root_hash(number.0 + 1)?,
                batch_hash: soft_confirmation.hash,
            });
        }

        let genesis_root = prover_storage.get_root_hash(1);
        if let Ok(state_root) = genesis_root {
            // Chain was initialized but no soft confirmations was processed
            debug!("Chain is already initialized. Skipping initialization.");
            return Ok(InitParams {
                state_root,
                batch_hash: [0; 32],
            });
        }

        info!("No history detected. Initializing chain...",);
        let storage = storage_manager.create_storage_on_l2_height(0)?;
        let (genesis_root, initialized_storage) = stf.init_chain(storage, genesis_config);
        storage_manager.save_change_set_l2(0, initialized_storage)?;
        storage_manager.finalize_l2(0)?;
        ledger_db.set_l2_genesis_state_root(&genesis_root)?;
        info!(
            "Chain initialization is done. Genesis root: 0x{}",
            hex::encode(genesis_root),
        );
        Ok(InitParams {
            state_root: genesis_root,
            batch_hash: [0; 32],
        })
    }
}
