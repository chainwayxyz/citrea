#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::FullNodeConfig;
use derive_more::Display;
use sov_db::ledger_db::LedgerDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_modules_api::{Context, DaSpec, Spec};
use sov_modules_stf_blueprint::{GenesisParams, Runtime as RuntimeTrait};
use sov_prover_storage_manager::{ProverStorage, ProverStorageManager, SnapshotManager};
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::{Zkvm, ZkvmHost};
use sov_stf_runner::{ProverGuestRunConfig, ProverService};
use tokio::sync::broadcast;

mod runtime_rpc;

pub use runtime_rpc::*;

/// The network currently running.
#[derive(Copy, Clone, Default, Debug, Display)]
pub enum Network {
    /// Mainnet
    #[default]
    Mainnet,
    /// Testnet
    Testnet,
    /// nightly
    Nightly,
}

/// This trait defines how to crate all the necessary dependencies required by a rollup.
#[async_trait]
pub trait RollupBlueprint: Sized + Send + Sync {
    /// Data Availability service.
    type DaService: DaService<Spec = Self::DaSpec, Error = anyhow::Error> + Send + Sync;

    /// A specification for the types used by a DA layer.
    type DaSpec: DaSpec + Send + Sync;

    /// Data Availability config.
    type DaConfig: Send + Sync;

    /// Data Availability verifier.
    type DaVerifier: DaVerifier + Send + Sync;

    /// Host of a zkVM program.
    type Vm: ZkvmHost + Zkvm + Send + Sync + 'static;

    /// Context for Zero Knowledge environment.
    type ZkContext: Context;

    /// Context for Native environment.
    type NativeContext: Context + Spec<Storage = ProverStorage<SnapshotManager>> + Sync + Send;

    /// Runtime for the Zero Knowledge environment.
    type ZkRuntime: RuntimeTrait<Self::ZkContext, Self::DaSpec> + Default;
    /// Runtime for the Native environment.
    type NativeRuntime: RuntimeTrait<Self::NativeContext, Self::DaSpec> + Default + Send + Sync;

    /// Prover service.
    type ProverService: ProverService<DaService = Self::DaService> + Send + Sync + 'static;

    /// Creates a new instance of the blueprint.
    fn new(network: Network) -> Self;

    /// Get batch proof guest code elfs by fork.
    fn get_batch_proof_elfs(&self) -> HashMap<SpecId, Vec<u8>>;

    /// Get light client guest code elfs by fork.
    fn get_light_client_elfs(&self) -> HashMap<SpecId, Vec<u8>>;

    /// Get batch prover code commitments by fork.
    fn get_batch_proof_code_commitments(
        &self,
    ) -> HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment>;

    /// Get light client prover code commitment.
    fn get_light_client_proof_code_commitment(
        &self,
    ) -> HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment>;

    /// Creates RPC methods for the rollup.
    fn create_rpc_methods(
        &self,
        storage: &ProverStorage<SnapshotManager>,
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
        task_manager: &mut TaskManager<()>,
    ) -> Result<Arc<Self::DaService>, anyhow::Error>;

    /// Creates instance of [`BitcoinDaVerifier`]
    fn create_da_verifier(&self) -> Self::DaVerifier;

    /// Creates instance of [`ProverService`].
    async fn create_prover_service(
        &self,
        proving_mode: ProverGuestRunConfig,
        da_service: &Arc<Self::DaService>,
        da_verifier: Self::DaVerifier,
        ledger_db: LedgerDB,
    ) -> Self::ProverService;

    /// Creates instance of [`Self::StorageManager`].
    /// Panics if initialization fails.
    fn create_storage_manager(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
    ) -> Result<ProverStorageManager<Self::DaSpec>, anyhow::Error>;

    /// Creates instance of a LedgerDB.
    fn create_ledger_db(&self, rocksdb_config: &RocksdbConfig) -> LedgerDB {
        LedgerDB::with_config(rocksdb_config).expect("Ledger DB failed to open")
    }
}
