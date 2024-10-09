use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use citrea_common::{FullNodeConfig, ProverConfig, SequencerConfig};
use citrea_fullnode::{CitreaFullnode, FullNode};
use citrea_primitives::forks::FORKS;
use citrea_prover::{CitreaProver, Prover};
use citrea_sequencer::{CitreaSequencer, Sequencer};
use sov_db::ledger_db::SharedLedgerOps;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::types::BatchNumber;
use sov_modules_api::storage::HierarchicalStorageManager;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::{Runtime as RuntimeTrait, StfBlueprint};
use sov_rollup_interface::fork::ForkManager;
use sov_state::storage::NativeStorage;
use sov_stf_runner::InitVariant;
use tokio::sync::broadcast;
use tracing::{info, instrument};

mod bitcoin;
mod mock;
pub use bitcoin::*;
pub use mock::*;

/// Overrides RollupBlueprint methods
#[async_trait]
pub trait CitreaRollupBlueprint: RollupBlueprint {
    /// Creates a new sequencer
    #[instrument(level = "trace", skip_all)]
    async fn create_new_sequencer(
        &self,
        runtime_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        sequencer_config: SequencerConfig,
    ) -> Result<Sequencer<Self>, anyhow::Error>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let da_service = self.create_da_service(&rollup_config, true).await?;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let rocksdb_config = RocksdbConfig::new(
            rollup_config.storage.path.as_path(),
            rollup_config.storage.db_max_open_files,
        );
        let ledger_db = self.create_ledger_db(&rocksdb_config);
        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        let (soft_confirmation_tx, soft_confirmation_rx) = broadcast::channel(10);
        // If subscriptions disabled, pass None
        let soft_confirmation_rx = if rollup_config.rpc.enable_subscriptions {
            Some(soft_confirmation_rx)
        } else {
            None
        };
        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods = self.create_rpc_methods(
            &prover_storage,
            &ledger_db,
            &da_service,
            None,
            soft_confirmation_rx,
        )?;

        let native_stf = StfBlueprint::new();

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

        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(BatchNumber(0));

        let mut fork_manager = ForkManager::new(FORKS.to_vec(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

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
            fork_manager,
            soft_confirmation_tx,
        )
        .unwrap();

        Ok(Sequencer {
            runner: seq,
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
        rollup_config: FullNodeConfig<Self::DaConfig>,
    ) -> Result<FullNode<Self>, anyhow::Error>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let da_service = self.create_da_service(&rollup_config, false).await?;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let rocksdb_config = RocksdbConfig::new(
            rollup_config.storage.path.as_path(),
            rollup_config.storage.db_max_open_files,
        );
        let ledger_db = self.create_ledger_db(&rocksdb_config);
        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        let runner_config = rollup_config.runner.expect("Runner config is missing");
        let (soft_confirmation_tx, soft_confirmation_rx) = broadcast::channel(10);
        // If subscriptions disabled, pass None
        let soft_confirmation_rx = if rollup_config.rpc.enable_subscriptions {
            Some(soft_confirmation_rx)
        } else {
            None
        };
        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods = self.create_rpc_methods(
            &prover_storage,
            &ledger_db,
            &da_service,
            Some(runner_config.sequencer_client_url.clone()),
            soft_confirmation_rx,
        )?;

        let native_stf = StfBlueprint::new();

        let genesis_root = prover_storage.get_root_hash(1);

        let init_variant = match ledger_db.get_head_soft_confirmation()? {
            // At least one soft confirmation was processed
            Some((number, soft_confirmation)) => {
                info!("Initialize node at batch number {:?}. State root: {:?}. Last soft confirmation hash: {:?}.", number, prover_storage.get_root_hash(number.0 + 1)?.as_ref(), soft_confirmation.hash);

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

        let code_commitments_by_spec = self.get_code_commitments_by_spec();

        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(BatchNumber(0));

        let mut fork_manager = ForkManager::new(FORKS.to_vec(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let runner = CitreaFullnode::new(
            runner_config,
            rollup_config.public_keys,
            rollup_config.rpc,
            da_service,
            ledger_db,
            native_stf,
            storage_manager,
            init_variant,
            code_commitments_by_spec,
            fork_manager,
            soft_confirmation_tx,
        )?;

        Ok(FullNode {
            runner,
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
        rollup_config: FullNodeConfig<Self::DaConfig>,
        prover_config: ProverConfig,
    ) -> Result<Prover<Self>, anyhow::Error>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let da_service = self.create_da_service(&rollup_config, true).await?;

        let rocksdb_config = RocksdbConfig::new(
            rollup_config.storage.path.as_path(),
            rollup_config.storage.db_max_open_files,
        );
        let ledger_db = self.create_ledger_db(&rocksdb_config);

        let prover_service = self
            .create_prover_service(
                prover_config.clone(),
                &rollup_config,
                &da_service,
                ledger_db.clone(),
            )
            .await;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        let (soft_confirmation_tx, soft_confirmation_rx) = broadcast::channel(10);
        // If subscriptions disabled, pass None
        let soft_confirmation_rx = if rollup_config.rpc.enable_subscriptions {
            Some(soft_confirmation_rx)
        } else {
            None
        };
        let runner_config = rollup_config.runner.expect("Runner config is missing");
        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods = self.create_rpc_methods(
            &prover_storage,
            &ledger_db,
            &da_service,
            Some(runner_config.sequencer_client_url.clone()),
            soft_confirmation_rx,
        )?;

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

        let code_commitments_by_spec = self.get_code_commitments_by_spec();

        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(BatchNumber(0));

        let mut fork_manager = ForkManager::new(FORKS.to_vec(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let runner = CitreaProver::new(
            runner_config,
            rollup_config.public_keys,
            rollup_config.rpc,
            da_service,
            ledger_db,
            native_stf,
            storage_manager,
            init_variant,
            Arc::new(prover_service),
            prover_config,
            code_commitments_by_spec,
            fork_manager,
            soft_confirmation_tx,
        )?;

        Ok(Prover {
            runner,
            rpc_methods,
        })
    }
}
