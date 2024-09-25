#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

mod runtime_rpc;
mod wallet;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
pub use runtime_rpc::*;
use sov_db::ledger_db::LedgerDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_modules_api::{Context, DaSpec, Spec};
use sov_modules_stf_blueprint::{GenesisParams, Runtime as RuntimeTrait};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::{Zkvm, ZkvmHost};
use sov_state::Storage;
use sov_stf_runner::{FullNodeConfig, ProverConfig, ProverService};
use tokio::sync::broadcast;
pub use wallet::*;

/// This trait defines how to crate all the necessary dependencies required by a rollup.
#[async_trait]
pub trait RollupBlueprint: Sized + Send + Sync {
    /// Data Availability service.
    type DaService: DaService<Spec = Self::DaSpec, Error = anyhow::Error> + Send + Sync;

    /// A specification for the types used by a DA layer.
    type DaSpec: DaSpec + Send + Sync;

    /// Data Availability config.
    type DaConfig: Send + Sync;

    /// Host of a zkVM program.
    type Vm: ZkvmHost + Zkvm + Send + Sync;

    /// Context for Zero Knowledge environment.
    type ZkContext: Context;

    /// Context for Native environment.
    type NativeContext: Context + Sync + Send;

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
        > + Send
        + Sync
        + 'static;

    /// Creates a new instance of the blueprint.
    fn new() -> Self;

    /// Get code commitments by fork.
    fn get_code_commitments_by_spec(&self) -> HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment>;

    /// Creates RPC methods for the rollup.
    fn create_rpc_methods(
        &self,
        storage: &<Self::NativeContext as Spec>::Storage,
        ledger_db: &LedgerDB,
        da_service: &Arc<Self::DaService>,
        sequencer_client_url: Option<String>,
        soft_confirmation_rx: Option<broadcast::Receiver<u64>>,
    ) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error>;

    /// Creates GenesisConfig from genesis files.
    #[allow(clippy::type_complexity)]
    fn create_genesis_config(
        &self,
        rt_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        _rollup_config: &FullNodeConfig<Self::DaConfig>,
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
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        require_wallet_check: bool,
    ) -> Result<Arc<Self::DaService>, anyhow::Error>;

    /// Creates instance of [`ProverService`].
    async fn create_prover_service(
        &self,
        prover_config: ProverConfig,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        da_service: &Arc<Self::DaService>,
        ledger_db: LedgerDB,
    ) -> Self::ProverService;

    /// Creates instance of [`Self::StorageManager`].
    /// Panics if initialization fails.
    fn create_storage_manager(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
    ) -> Result<Self::StorageManager, anyhow::Error>;

    /// Creates instance of a LedgerDB.
    fn create_ledger_db(&self, rocksdb_config: &RocksdbConfig) -> LedgerDB {
        LedgerDB::with_config(rocksdb_config).expect("Ledger DB failed to open")
    }
}
