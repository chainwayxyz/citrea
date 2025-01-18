use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use citrea_batch_prover::da_block_handler::L1BlockHandler as BatchProverL1BlockHandler;
use citrea_batch_prover::CitreaBatchProver;
use citrea_common::cache::L1BlockCache;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::{
    BatchProverConfig, FullNodeConfig, LightClientProverConfig, RollupPublicKeys, SequencerConfig,
};
use citrea_fullnode::da_block_handler::L1BlockHandler as FullNodeL1BlockHandler;
use citrea_fullnode::CitreaFullnode;
use citrea_light_client_prover::da_block_handler::L1BlockHandler as LightClientProverL1BlockHandler;
use citrea_light_client_prover::runner::CitreaLightClientProver;
use citrea_primitives::forks::get_forks;
use citrea_sequencer::CitreaSequencer;
use jsonrpsee::RpcModule;
use sov_db::ledger_db::migrations::{LedgerDBMigrator, Migrations};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::mmr_db::MmrDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::types::SoftConfirmationNumber;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{Spec, Zkvm};
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::{
    GenesisParams as StfGenesisParams, Runtime as RuntimeTrait, StfBlueprint,
};
use sov_prover_storage_manager::{ProverStorageManager, SnapshotManager};
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::storage::NativeStorage;
use sov_state::{ArrayWitness, ProverStorage};
use sov_stf_runner::InitVariant;
use tokio::sync::{broadcast, Mutex};
use tracing::{info, instrument};

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
    ) -> Result<Dependencies<Self>> {
        let mut task_manager = TaskManager::default();
        let da_service = self
            .create_da_service(&rollup_config, true, &mut task_manager)
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
            &prover_storage,
            &ledger_db,
            &da_service,
            sequencer_client_url,
            soft_confirmation_rx,
        )
    }

    /// Creates a new sequencer
    #[instrument(level = "trace", skip_all)]
    fn create_sequencer(
        &self,
        genesis_config: GenesisParams<Self>,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        sequencer_config: SequencerConfig,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        ledger_db: LedgerDB,
        storage_manager: ProverStorageManager<<Self as RollupBlueprint>::DaSpec>,
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
        self.run_ledger_migrations(
            &rollup_config,
            citrea_sequencer::db_migrations::migrations(),
        )?;

        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(SoftConfirmationNumber(0));

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let genesis_root = prover_storage.get_root_hash(1);
        let init_variant = match ledger_db.get_head_soft_confirmation()? {
            // At least one soft confirmation was processed
            Some((number, soft_confirmation)) => {
                info!("Initialize sequencer at batch number {:?}. State root: {:?}. Last soft confirmation hash: {:?}.", number, prover_storage.get_root_hash(number.0 + 1)?.as_ref(), soft_confirmation.hash);

                InitVariant::Initialized((
                    prover_storage.get_root_hash(number.0 + 1)?,
                    soft_confirmation.hash,
                ))
            }
            None => {
                info!("Initialize sequencer at genesis.");
                match genesis_root {
                    // Chain was initialized but no soft confirmations was processed
                    Ok(root_hash) => InitVariant::Initialized((root_hash, [0; 32])),
                    // Not even initialized
                    _ => InitVariant::Genesis(genesis_config),
                }
            }
        };
        citrea_sequencer::build_services(
            sequencer_config,
            init_variant,
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
    async fn create_full_node(
        &self,
        genesis_config: GenesisParams<Self>,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        ledger_db: LedgerDB,
        storage_manager: ProverStorageManager<<Self as RollupBlueprint>::DaSpec>,
        prover_storage: ProverStorage<SnapshotManager>,
        soft_confirmation_tx: broadcast::Sender<u64>,
        rpc_module: RpcModule<()>,
    ) -> Result<(
        CitreaFullnode<Self::DaService, Self::NativeContext, LedgerDB, Self::NativeRuntime>,
        FullNodeL1BlockHandler<
            Self::NativeContext,
            Self::Vm,
            Self::DaService,
            StorageRootHash,
            LedgerDB,
        >,
        RpcModule<()>,
    )>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        self.run_ledger_migrations(&rollup_config, citrea_fullnode::db_migrations::migrations())?;

        let runner_config = rollup_config.runner.expect("Runner config is missing");

        let genesis_root = prover_storage.get_root_hash(1);
        let head_sc = ledger_db.get_head_soft_confirmation()?;
        let init_variant = match head_sc {
            // At least one soft confirmation was processed
            Some((number, soft_confirmation)) => {
                let state_root = prover_storage.get_root_hash(number.0 + 1)?;
                info!("Initialize node at batch number {:?}. State root: {:?}. Last soft confirmation hash: {:?}.", number, state_root.as_ref(), soft_confirmation.hash);

                InitVariant::Initialized((
                    prover_storage.get_root_hash(number.0 + 1)?,
                    soft_confirmation.hash,
                ))
            }
            None => {
                info!("Initialize node at genesis.");
                match genesis_root {
                    // Chain was initialized but no soft confirmations was processed
                    Ok(root_hash) => InitVariant::Initialized((root_hash, [0; 32])),
                    // Not even initialized
                    _ => InitVariant::Genesis(genesis_config),
                }
            }
        };

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
            init_variant,
            rollup_config.public_keys,
            da_service,
            ledger_db,
            storage_manager,
            soft_confirmation_tx,
            fork_manager,
            code_commitments,
            rpc_module,
        )
    }

    /// Creates a new prover
    #[instrument(level = "trace", skip_all)]
    async fn create_batch_prover(
        &self,
        genesis_config: GenesisParams<Self>,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        ledger_db: LedgerDB,
        storage_manager: ProverStorageManager<<Self as RollupBlueprint>::DaSpec>,
        prover_storage: ProverStorage<SnapshotManager>,
        soft_confirmation_tx: broadcast::Sender<u64>,
        task_manager: TaskManager<()>,
    ) -> Result<
        CitreaBatchProver<Self::NativeContext, Self::DaService, LedgerDB, Self::NativeRuntime>,
    >
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        self.run_ledger_migrations(
            &rollup_config,
            citrea_batch_prover::db_migrations::migrations(),
        )?;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let runner_config = rollup_config.runner.expect("Runner config is missing");

        let native_stf = StfBlueprint::new();
        let genesis_root = prover_storage.get_root_hash(1);
        let init_variant = match ledger_db.get_head_soft_confirmation()? {
            // At least one soft confirmation was processed
            Some((number, soft_confirmation)) => {
                info!("Initialize prover at batch number {:?}. State root: {:?}. Last soft confirmation hash: {:?}.", number, prover_storage.get_root_hash(number.0 + 1)?.as_ref(), soft_confirmation.hash);

                InitVariant::Initialized((
                    prover_storage.get_root_hash(number.0 + 1)?,
                    soft_confirmation.hash,
                ))
            }
            None => {
                info!("Initialize prover at genesis.");
                match genesis_root {
                    // Chain was initialized but no soft confirmations was processed
                    Ok(root_hash) => InitVariant::Initialized((root_hash, [0; 32])),
                    // Not even initialized
                    _ => InitVariant::Genesis(genesis_config),
                }
            }
        };

        let current_l2_height = ledger_db
            .get_head_soft_confirmation_height()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .unwrap_or(0);

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let runner = CitreaBatchProver::new(
            runner_config,
            rollup_config.public_keys,
            da_service,
            ledger_db,
            native_stf,
            storage_manager,
            init_variant,
            fork_manager,
            soft_confirmation_tx,
            task_manager,
        )?;

        Ok(runner)
    }

    /// Creates a new light client prover
    #[instrument(level = "trace", skip_all)]
    async fn create_light_client_prover(
        &self,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        ledger_db: LedgerDB,
        task_manager: TaskManager<()>,
    ) -> Result<CitreaLightClientProver<LedgerDB>>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        self.run_ledger_migrations(
            &rollup_config,
            citrea_light_client_prover::db_migrations::migrations(),
        )?;

        let runner_config = rollup_config.runner.expect("Runner config is missing");

        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(SoftConfirmationNumber(0));

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let runner = CitreaLightClientProver::new(runner_config, ledger_db, task_manager)?;

        Ok(runner)
    }

    /// Create the batch prover DA block handler
    async fn create_batch_prover_l1_block_handler(
        &self,
        prover_config: BatchProverConfig,
        ledger_db: LedgerDB,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        public_keys: RollupPublicKeys,
        code_commitments_by_spec: HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment>,
    ) -> BatchProverL1BlockHandler<
        Self::Vm,
        Self::DaService,
        Self::ProverService,
        LedgerDB,
        StorageRootHash,
        ArrayWitness,
        Transaction<<Self as RollupBlueprint>::NativeContext>,
    > {
        let skip_submission_until_l1 = std::env::var("SKIP_PROOF_SUBMISSION_UNTIL_L1")
            .map_or(0u64, |v| v.parse().unwrap_or(0));
        let elfs_by_spec = self.get_batch_proof_elfs();
        let prover_service = Arc::new(
            self.create_prover_service(
                prover_config.proving_mode,
                &da_service,
                ledger_db.clone(),
                prover_config.proof_sampling_number,
            )
            .await,
        );
        BatchProverL1BlockHandler::new(
            prover_config,
            prover_service,
            ledger_db,
            da_service,
            public_keys.sequencer_public_key,
            public_keys.sequencer_da_pub_key,
            code_commitments_by_spec,
            elfs_by_spec,
            skip_submission_until_l1,
            Arc::new(Mutex::new(L1BlockCache::new())),
        )
    }

    /// Create the light client prover DA block handler
    async fn create_light_client_prover_l1_block_handler(
        &self,
        prover_config: LightClientProverConfig,
        rocksdb_config: &RocksdbConfig,
        ledger_db: LedgerDB,
        da_service: Arc<<Self as RollupBlueprint>::DaService>,
        public_keys: RollupPublicKeys,
        batch_prover_code_commitments: HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment>,
    ) -> anyhow::Result<
        LightClientProverL1BlockHandler<Self::Vm, Self::DaService, Self::ProverService, LedgerDB>,
    > {
        let light_client_prover_code_commitments = self.get_light_client_proof_code_commitment();
        let light_client_prover_elfs = self.get_light_client_elfs();
        let prover_service = Arc::new(
            self.create_prover_service(
                prover_config.proving_mode,
                &da_service,
                ledger_db.clone(),
                prover_config.proof_sampling_number,
            )
            .await,
        );
        let mmr_db = MmrDB::new(&rocksdb_config)?;
        Ok(LightClientProverL1BlockHandler::new(
            prover_config,
            prover_service,
            ledger_db,
            da_service,
            public_keys.prover_da_pub_key,
            batch_prover_code_commitments,
            light_client_prover_code_commitments,
            light_client_prover_elfs,
            mmr_db,
        ))
    }

    /// Run Ledger DB migrations
    fn run_ledger_migrations(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        migrations: Migrations,
    ) -> anyhow::Result<()> {
        // Migrate before constructing ledger_db instance so that no lock is present.
        let migrator = LedgerDBMigrator::new(rollup_config.storage.path.as_path(), &migrations);
        migrator.migrate(rollup_config.storage.db_max_open_files)?;
        Ok(())
    }
}
