#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::{FullNodeConfig, ProverGuestRunConfig};
use citrea_stf::runtime::CitreaRuntime;
use prover_services::ParallelProverService;
use sov_db::ledger_db::LedgerDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::DaSpec;
use sov_modules_stf_blueprint::{GenesisParams, Runtime as RuntimeTrait};
use sov_prover_storage_manager::{ProverStorage, ProverStorageManager, SnapshotManager};
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::{Zkvm, ZkvmHost};
use sov_rollup_interface::Network;
use tokio::sync::broadcast;

mod runtime_rpc;

pub use runtime_rpc::*;

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
    fn get_light_client_proof_code_commitments(
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
        rt_genesis_paths: &<CitreaRuntime<DefaultContext, Self::DaSpec> as RuntimeTrait<
            DefaultContext,
            Self::DaSpec,
        >>::GenesisPaths,
        _rollup_config: &FullNodeConfig<Self::DaConfig>,
    ) -> anyhow::Result<
        GenesisParams<
            <CitreaRuntime<DefaultContext, Self::DaSpec> as RuntimeTrait<
                DefaultContext,
                Self::DaSpec,
            >>::GenesisConfig,
        >,
    > {
        let rt_genesis = <CitreaRuntime<DefaultContext, Self::DaSpec> as RuntimeTrait<
            DefaultContext,
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
        ledger_db: LedgerDB,
        proof_sampling_number: usize,
        is_light_client_prover: bool,
    ) -> ParallelProverService<Self::DaService, Self::Vm>;

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
