use async_trait::async_trait;
pub use bitcoin::*;
use citrea_fullnode::{CitreaFullnode, FullNode};
use citrea_prover::{CitreaProver, Prover};
use citrea_sequencer::{CitreaSequencer, Sequencer, SequencerConfig};
pub use mock::*;
use sov_modules_api::storage::HierarchicalStorageManager;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::{Runtime as RuntimeTrait, StfBlueprint};
use sov_state::storage::NativeStorage;
use sov_stf_runner::{FullNodeConfig, InitVariant, ProverConfig};
use tracing::instrument;
mod bitcoin;
mod mock;

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
        let da_service = self.create_da_service(&rollup_config).await;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let ledger_db = self.create_ledger_db(&rollup_config);
        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods =
            self.create_rpc_methods(&prover_storage, &ledger_db, &da_service, None)?;

        let native_stf = StfBlueprint::new();

        let genesis_root = prover_storage.get_root_hash(1);

        let prev_data = match ledger_db.get_head_soft_batch()? {
            Some((number, soft_batch)) => {
                Some((prover_storage.get_root_hash(number.0 + 1)?, soft_batch.hash))
            }
            None => None,
        };
        let init_variant = match prev_data {
            Some((root_hash, batch_hash)) => InitVariant::Initialized((root_hash, batch_hash)),
            None => match genesis_root {
                Ok(root_hash) => InitVariant::Initialized((root_hash, [0; 32])),
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
        let da_service = self.create_da_service(&rollup_config).await;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let ledger_db = self.create_ledger_db(&rollup_config);
        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

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

        let prev_data = match ledger_db.get_head_soft_batch()? {
            Some((number, soft_batch)) => {
                Some((prover_storage.get_root_hash(number.0 + 1)?, soft_batch.hash))
            }
            None => None,
        };
        let init_variant = match prev_data {
            Some((root_hash, batch_hash)) => InitVariant::Initialized((root_hash, batch_hash)),
            None => match genesis_root {
                Ok(root_hash) => InitVariant::Initialized((root_hash, [0; 32])),
                _ => InitVariant::Genesis(genesis_config),
            },
        };

        let code_commitment = self.get_code_commitment();

        let runner = CitreaFullnode::new(
            runner_config,
            rollup_config.public_keys,
            rollup_config.rpc,
            da_service,
            ledger_db,
            native_stf,
            storage_manager,
            init_variant,
            code_commitment,
            rollup_config.sync_blocks_count,
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

        let prev_data = match ledger_db.get_head_soft_batch()? {
            Some((number, soft_batch)) => {
                Some((prover_storage.get_root_hash(number.0 + 1)?, soft_batch.hash))
            }
            None => None,
        };
        let init_variant = match prev_data {
            Some((root_hash, batch_hash)) => InitVariant::Initialized((root_hash, batch_hash)),
            None => match genesis_root {
                Ok(root_hash) => InitVariant::Initialized((root_hash, [0; 32])),
                _ => InitVariant::Genesis(genesis_config),
            },
        };

        let code_commitment = self.get_code_commitment();

        let runner = CitreaProver::new(
            runner_config,
            rollup_config.public_keys,
            rollup_config.rpc,
            da_service,
            ledger_db,
            native_stf,
            storage_manager,
            init_variant,
            Some(prover_service),
            Some(prover_config),
            code_commitment,
            rollup_config.sync_blocks_count,
        )?;

        Ok(Prover {
            runner,
            rpc_methods,
        })
    }
}
