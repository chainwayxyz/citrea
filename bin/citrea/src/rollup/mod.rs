use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use citrea_batch_prover::l1_syncer::L1Syncer as BatchProverL1Syncer;
use citrea_batch_prover::prover::Prover;
use citrea_batch_prover::L2Syncer as BatchProverL2Syncer;
use citrea_common::backup::BackupManager;
use citrea_common::{
    BatchProverConfig, FullNodeConfig, InitParams, LightClientProverConfig, NodeType,
    SequencerConfig,
};
use citrea_fullnode::da_block_handler::L1BlockHandler as FullNodeL1BlockHandler;
use citrea_fullnode::L2Syncer as FullNodeL2Syncer;
use citrea_light_client_prover::circuit::initial_values::InitialValueProvider;
use citrea_light_client_prover::da_block_handler::L1BlockHandler as LightClientProverL1BlockHandler;
use citrea_primitives::forks::get_forks;
use citrea_sequencer::CitreaSequencer;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use citrea_storage_ops::pruning::PrunerService;
use citrea_storage_ops::rollback::Rollback;
use jsonrpsee::RpcModule;
use reth_tasks::{TaskExecutor, TaskManager};
use sov_db::ledger_db::migrations::{LedgerDBMigrator, Migrations};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::types::L2BlockNumber;
use sov_db::state_db::StateDB;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::{
    GenesisParams as StfGenesisParams, Runtime as RuntimeTrait, StfBlueprint,
};
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::Network;
use sov_state::storage::NativeStorage;
use tokio::sync::broadcast;
use tracing::{debug, info, instrument};

mod bitcoin;
mod mock;
pub use bitcoin::*;
pub use mock::*;

type GenesisParams<T> = StfGenesisParams<
    <CitreaRuntime<DefaultContext, <T as RollupBlueprint>::DaSpec> as RuntimeTrait<
        DefaultContext,
        <T as RollupBlueprint>::DaSpec,
    >>::GenesisConfig,
>;

/// Group for storage instances
pub struct Storage {
    /// The ledger DB instance
    pub ledger_db: LedgerDB,
    /// The prover storage manager instance.
    pub storage_manager: ProverStorageManager,
}

/// Group for initialization dependencies
pub struct Dependencies<T: RollupBlueprint> {
    /// The task manager
    pub task_manager: TaskManager,
    /// The DA service
    pub da_service: Arc<<T as RollupBlueprint>::DaService>,
    /// The channel on which L2 block number is broadcasted.
    pub l2_block_channel: (broadcast::Sender<u64>, Option<broadcast::Receiver<u64>>),
}

/// Overrides RollupBlueprint methods
#[async_trait]
pub trait CitreaRollupBlueprint: RollupBlueprint {
    /// Setup the rollup's dependencies
    async fn setup_dependencies(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        require_da_wallet: bool,
        network: Network,
    ) -> Result<Dependencies<Self>> {
        let task_manager = TaskManager::current();
        let da_service = self
            .create_da_service(
                rollup_config,
                require_da_wallet,
                task_manager.executor(),
                network,
            )
            .await?;
        let (l2_block_tx, l2_block_rx) = broadcast::channel(10);
        // If subscriptions disabled, pass None
        let l2_block_rx = if rollup_config.rpc.enable_subscriptions {
            Some(l2_block_rx)
        } else {
            None
        };

        Ok(Dependencies {
            task_manager,
            da_service,
            l2_block_channel: (l2_block_tx, l2_block_rx),
        })
    }

    /// Setup the rollup's storage access
    fn setup_storage(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        rocksdb_config: &RocksdbConfig,
        backup_manager: &Arc<BackupManager>,
    ) -> Result<Storage> {
        let ledger_db = self.create_ledger_db(rocksdb_config);
        let storage_manager = self.create_storage_manager(rollup_config)?;

        backup_manager
            .register_database(LedgerDB::DB_PATH_SUFFIX.to_string(), ledger_db.db_handle())?;
        backup_manager.register_database(
            StateDB::DB_PATH_SUFFIX.to_string(),
            storage_manager.get_state_db_handle(),
        )?;
        backup_manager.register_database(
            NativeDB::DB_PATH_SUFFIX.to_string(),
            storage_manager.get_native_db_handle(),
        )?;

        Ok(Storage {
            ledger_db,
            storage_manager,
        })
    }

    /// In case of an interrupt between l2 block commits of StateDB and LedgerDB,
    /// this function rollbacks dbs to the LedgerDB version.
    async fn sync_ledger_and_state_db(
        &self,
        ledger_db: &LedgerDB,
        storage_manager: &ProverStorageManager,
        node_type: NodeType,
    ) -> Result<()> {
        let next_version = StateDB::new(storage_manager.get_state_db_handle()).next_version();
        let state_version = if next_version >= 2 {
            next_version - 2
        } else {
            return Ok(()); // no l2 blocks processed
        };

        let ledger_version = ledger_db
            .get_head_l2_block_height()
            .context("Failed to get head l2 block")?
            .unwrap_or(0);

        if state_version == (ledger_version + 1) {
            tracing::debug!(
                "Version mismatch. LedgerDB version: {}, StateDB version: {}. Rolling back to LedgerDB version.",
                ledger_version,
                state_version
            );
            let rollback = Rollback::new(
                ledger_db.inner(),
                storage_manager.get_state_db_handle(),
                storage_manager.get_native_db_handle(),
            );
            let l1_target = ledger_db
                .get_last_scanned_l1_height()?
                .map(|height| height.0)
                .unwrap_or(0);
            let last_sequencer_commitment_index = ledger_db
                .get_last_commitment()?
                .map(|commitment| commitment.index)
                .unwrap_or(0);

            rollback
                .execute(
                    node_type,
                    Some(ledger_version), // rollback to ledger version
                    Some(l1_target),
                    Some(last_sequencer_commitment_index),
                )
                .await?;
        } else if state_version == ledger_version {
            tracing::debug!(
                "LedgerDB version is equal to StateDB version: {}",
                ledger_version
            );
        } else {
            anyhow::bail!(
                "Storage is corrupted, LedgerDB version: {}, StateDB version: {}",
                ledger_version,
                state_version
            );
        }
        return Ok(());
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
        storage_manager: ProverStorageManager,
        l2_block_tx: broadcast::Sender<u64>,
        rpc_module: RpcModule<()>,
        backup_manager: Arc<BackupManager>,
        task_executor: TaskExecutor,
    ) -> Result<(CitreaSequencer<Self::DaService>, RpcModule<()>)> {
        let current_l2_height = ledger_db
            .get_head_l2_block()
            .map_err(|e| anyhow!("Failed to get head l2 block: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(L2BlockNumber(0));

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let native_stf = StfBlueprint::new();
        let init_params =
            self.init_chain(genesis_config, &native_stf, &ledger_db, &storage_manager)?;

        citrea_sequencer::build_services(
            sequencer_config,
            init_params,
            native_stf,
            rollup_config.public_keys,
            da_service,
            ledger_db,
            storage_manager,
            l2_block_tx,
            fork_manager,
            rpc_module,
            backup_manager,
            task_executor,
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
        storage_manager: ProverStorageManager,
        l2_block_tx: broadcast::Sender<u64>,
        rpc_module: RpcModule<()>,
        backup_manager: Arc<BackupManager>,
    ) -> Result<(
        FullNodeL2Syncer<Self::DaService, LedgerDB>,
        FullNodeL1BlockHandler<Self::Vm, Self::DaService, LedgerDB>,
        Option<PrunerService>,
        RpcModule<()>,
    )> {
        let runner_config = rollup_config.runner.expect("Runner config is missing");

        let native_stf = StfBlueprint::new();

        self.sync_ledger_and_state_db(&ledger_db, &storage_manager, NodeType::FullNode)
            .await?;
        let init_params =
            self.init_chain(genesis_config, &native_stf, &ledger_db, &storage_manager)?;

        let current_l2_height = ledger_db
            .get_head_l2_block_height()
            .map_err(|e| anyhow!("Failed to get head l2 block: {}", e))?
            .unwrap_or(0);

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height);
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
            l2_block_tx,
            fork_manager,
            code_commitments,
            rpc_module,
            backup_manager,
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
        storage_manager: ProverStorageManager,
        l2_block_tx: broadcast::Sender<u64>,
        rpc_module: RpcModule<()>,
        backup_manager: Arc<BackupManager>,
    ) -> Result<(
        BatchProverL2Syncer<Self::DaService, LedgerDB>,
        BatchProverL1Syncer<Self::DaService, LedgerDB>,
        Prover<Self::DaService, LedgerDB, Self::Vm>,
        RpcModule<()>,
    )> {
        let runner_config = rollup_config.runner.expect("Runner config is missing");

        let native_stf = StfBlueprint::new();

        self.sync_ledger_and_state_db(&ledger_db, &storage_manager, NodeType::BatchProver)
            .await?;
        let init_params =
            self.init_chain(genesis_config, &native_stf, &ledger_db, &storage_manager)?;

        let current_l2_height = ledger_db
            .get_head_l2_block_height()
            .map_err(|e| anyhow!("Failed to get head l2 block: {}", e))?
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
            l2_block_tx,
            fork_manager,
            code_commitments,
            elfs,
            rpc_module,
            backup_manager,
        )
        .await
    }

    /// Creates a new light client prover
    #[instrument(level = "trace", skip_all)]
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    async fn create_light_client_prover(
        &self,
        network: Network,
        prover_config: LightClientProverConfig,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        ledger_db: LedgerDB,
        storage_manager: ProverStorageManager,
        rpc_module: RpcModule<()>,
        backup_manager: Arc<BackupManager>,
    ) -> Result<(
        LightClientProverL1BlockHandler<Self::Vm, Self::DaService, LedgerDB>,
        RpcModule<()>,
    )>
    where
        Network: InitialValueProvider<Self::DaSpec>,
    {
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

        let code_commitments = self.get_light_client_proof_code_commitments();
        let elfs = self.get_light_client_elfs();

        citrea_light_client_prover::build_services(
            network,
            prover_config,
            storage_manager,
            ledger_db,
            da_service,
            prover_service,
            code_commitments,
            elfs,
            rpc_module,
            backup_manager,
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
        stf: &StfBlueprint<
            DefaultContext,
            Self::DaSpec,
            CitreaRuntime<DefaultContext, Self::DaSpec>,
        >,
        ledger_db: &LedgerDB,
        storage_manager: &ProverStorageManager,
    ) -> anyhow::Result<InitParams> {
        let prover_storage = storage_manager.create_storage_for_next_l2_height();

        if let Some((number, l2_block)) = ledger_db.get_head_l2_block()? {
            // At least one l2 block was processed
            info!(
                "Initialize node at L2 height #{}. State root: 0x{}. Last l2 block hash: 0x{}.",
                number.0,
                hex::encode(prover_storage.get_root_hash(number.0 + 1)?),
                hex::encode(l2_block.hash)
            );

            return Ok(InitParams {
                prev_state_root: prover_storage.get_root_hash(number.0 + 1)?,
                prev_l2_block_hash: l2_block.hash,
            });
        }

        let genesis_root = prover_storage.get_root_hash(1);
        if let Ok(prev_state_root) = genesis_root {
            // Chain was initialized but no L2 blocks were processed
            debug!("Chain is already initialized. Skipping initialization.");
            return Ok(InitParams {
                prev_state_root,
                prev_l2_block_hash: [0; 32],
            });
        }

        info!("No history detected. Initializing chain...",);
        assert_eq!(prover_storage.version(), 0, "Init version must be 0");

        let (genesis_root, initialized_storage) = stf.init_chain(prover_storage, genesis_config);
        storage_manager.finalize_storage(initialized_storage);
        ledger_db.set_l2_genesis_state_root(&genesis_root)?;
        info!(
            "Chain initialization is done. Genesis root: 0x{}",
            hex::encode(genesis_root),
        );
        Ok(InitParams {
            prev_state_root: genesis_root,
            prev_l2_block_hash: [0; 32],
        })
    }
}
