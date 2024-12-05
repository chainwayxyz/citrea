use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin_da::rpc::create_rpc_module as create_da_rpc_module;
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig, TxidWrapper};
use bitcoin_da::spec::{BitcoinSpec, RollupParams};
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_common::rpc::register_healthcheck_rpc;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::FullNodeConfig;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use citrea_risc0_adapter::host::Risc0BonsaiHost;
// use citrea_sp1::host::SP1Host;
use citrea_stf::genesis_config::StorageConfig;
use citrea_stf::runtime::Runtime;
use citrea_stf::verifier::StateTransitionVerifier;
use prover_services::{ParallelProverService, ProofGenMode};
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::{DefaultContext, ZkDefaultContext};
use sov_modules_api::{Address, SpecId, Zkvm};
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::{ProverStorageManager, SnapshotManager};
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::services::da::SenderWithNotifier;
use sov_state::{ProverStorage, ZkStorage};
use sov_stf_runner::ProverGuestRunConfig;
use tokio::sync::broadcast;
use tokio::sync::mpsc::unbounded_channel;
use tracing::instrument;

use crate::guests::{
    BATCH_PROOF_LATEST_BITCOIN_GUESTS, BATCH_PROOF_MAINNET_GUESTS, BATCH_PROOF_TESTNET_GUESTS,
    LIGHT_CLIENT_LATEST_BITCOIN_GUESTS, LIGHT_CLIENT_MAINNET_GUESTS, LIGHT_CLIENT_TESTNET_GUESTS,
};
use crate::{CitreaRollupBlueprint, Network};

/// Rollup with BitcoinDa
pub struct BitcoinRollup {
    network: Network,
}

impl CitreaRollupBlueprint for BitcoinRollup {}

#[async_trait]
impl RollupBlueprint for BitcoinRollup {
    type DaService = BitcoinService;
    type DaSpec = BitcoinSpec;
    type DaConfig = BitcoinServiceConfig;
    type DaVerifier = BitcoinVerifier;
    type Vm = Risc0BonsaiHost;
    type ZkContext = ZkDefaultContext;
    type NativeContext = DefaultContext;

    type ZkRuntime = Runtime<Self::ZkContext, Self::DaSpec>;
    type NativeRuntime = Runtime<Self::NativeContext, Self::DaSpec>;

    type ProverService = ParallelProverService<
        Self::DaService,
        Self::Vm,
        StfBlueprint<Self::ZkContext, Self::DaSpec, Self::ZkRuntime>,
    >;

    fn new(network: Network) -> Self {
        Self { network }
    }

    #[instrument(level = "trace", skip_all, err)]
    fn create_rpc_methods(
        &self,
        storage: &ProverStorage<SnapshotManager>,
        ledger_db: &LedgerDB,
        da_service: &Arc<Self::DaService>,
        sequencer_client_url: Option<String>,
        soft_confirmation_rx: Option<broadcast::Receiver<u64>>,
    ) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error> {
        // unused inside register RPC
        let sov_sequencer = Address::new([0; 32]);

        #[allow(unused_mut)]
        let mut rpc_methods = sov_modules_rollup_blueprint::register_rpc::<
            Self::NativeRuntime,
            Self::NativeContext,
            Self::DaService,
        >(storage, ledger_db, da_service, sov_sequencer)?;

        crate::eth::register_ethereum::<Self::DaService>(
            da_service.clone(),
            storage.clone(),
            ledger_db.clone(),
            &mut rpc_methods,
            sequencer_client_url,
            soft_confirmation_rx,
        )?;

        register_healthcheck_rpc(&mut rpc_methods, ledger_db.clone())?;

        let da_methods = create_da_rpc_module(da_service.clone());
        rpc_methods.merge(da_methods)?;

        Ok(rpc_methods)
    }

    #[instrument(level = "trace", skip_all, err)]
    fn create_storage_manager(
        &self,
        rollup_config: &citrea_common::FullNodeConfig<Self::DaConfig>,
    ) -> Result<ProverStorageManager<Self::DaSpec>, anyhow::Error> {
        let storage_config = StorageConfig {
            path: rollup_config.storage.path.clone(),
            db_max_open_files: rollup_config.storage.db_max_open_files,
        };
        ProverStorageManager::new(storage_config)
    }

    #[instrument(level = "trace", skip_all)]
    async fn create_da_service(
        &self,
        rollup_config: &FullNodeConfig<Self::DaConfig>,
        require_wallet_check: bool,
        task_manager: &mut TaskManager<()>,
    ) -> Result<Arc<Self::DaService>, anyhow::Error> {
        let (tx, rx) = unbounded_channel::<SenderWithNotifier<TxidWrapper>>();

        let bitcoin_service = if require_wallet_check {
            BitcoinService::new_with_wallet_check(
                rollup_config.da.clone(),
                RollupParams {
                    to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
                    to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
                },
                tx,
            )
            .await?
        } else {
            BitcoinService::new_without_wallet_check(
                rollup_config.da.clone(),
                RollupParams {
                    to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
                    to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
                },
                tx,
            )
            .await?
        };
        let service = Arc::new(bitcoin_service);
        // until forced transactions are implemented,
        // require_wallet_check is set false for full nodes.
        if require_wallet_check {
            // run only for sequencer and prover
            service.monitoring.restore().await?;

            task_manager.spawn(|tk| Arc::clone(&service).run_da_queue(rx, tk));
            task_manager.spawn(|tk| Arc::clone(&service.monitoring).run(tk));
        }

        Ok(service)
    }

    fn create_da_verifier(&self) -> Self::DaVerifier {
        BitcoinVerifier::new(RollupParams {
            to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
            to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
        })
    }

    fn get_batch_proof_elfs(&self) -> HashMap<SpecId, Vec<u8>> {
        match self.network {
            Network::Mainnet => BATCH_PROOF_MAINNET_GUESTS
                .iter()
                .map(|(k, (_, code))| (*k, code.clone()))
                .collect(),
            Network::Testnet => BATCH_PROOF_TESTNET_GUESTS
                .iter()
                .map(|(k, (_, code))| (*k, code.clone()))
                .collect(),
            Network::Nightly => BATCH_PROOF_LATEST_BITCOIN_GUESTS
                .iter()
                .map(|(k, (_, code))| (*k, code.clone()))
                .collect(),
        }
    }

    fn get_light_client_elfs(&self) -> HashMap<SpecId, Vec<u8>> {
        match self.network {
            Network::Mainnet => LIGHT_CLIENT_MAINNET_GUESTS
                .iter()
                .map(|(k, (_, code))| (*k, code.clone()))
                .collect(),
            Network::Testnet => LIGHT_CLIENT_TESTNET_GUESTS
                .iter()
                .map(|(k, (_, code))| (*k, code.clone()))
                .collect(),
            Network::Nightly => LIGHT_CLIENT_LATEST_BITCOIN_GUESTS
                .iter()
                .map(|(k, (_, code))| (*k, code.clone()))
                .collect(),
        }
    }

    fn get_batch_proof_code_commitments(
        &self,
    ) -> HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment> {
        match self.network {
            Network::Mainnet => BATCH_PROOF_MAINNET_GUESTS
                .iter()
                .map(|(k, (id, _))| (*k, *id))
                .collect(),
            Network::Testnet => BATCH_PROOF_TESTNET_GUESTS
                .iter()
                .map(|(k, (id, _))| (*k, *id))
                .collect(),
            Network::Nightly => BATCH_PROOF_LATEST_BITCOIN_GUESTS
                .iter()
                .map(|(k, (id, _))| (*k, *id))
                .collect(),
        }
    }

    fn get_light_client_proof_code_commitment(
        &self,
    ) -> HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment> {
        match self.network {
            Network::Mainnet => LIGHT_CLIENT_MAINNET_GUESTS
                .iter()
                .map(|(k, (id, _))| (*k, *id))
                .collect(),
            Network::Testnet => LIGHT_CLIENT_TESTNET_GUESTS
                .iter()
                .map(|(k, (id, _))| (*k, *id))
                .collect(),
            Network::Nightly => LIGHT_CLIENT_LATEST_BITCOIN_GUESTS
                .iter()
                .map(|(k, (id, _))| (*k, *id))
                .collect(),
        }
    }

    #[instrument(level = "trace", skip_all)]
    async fn create_prover_service(
        &self,
        proving_mode: ProverGuestRunConfig,
        da_service: &Arc<Self::DaService>,
        da_verifier: Self::DaVerifier,
        ledger_db: LedgerDB,
    ) -> Self::ProverService {
        let vm = Risc0BonsaiHost::new(ledger_db.clone());
        // let vm = SP1Host::new(
        //     include_bytes!("../guests/sp1/batch-prover-bitcoin/elf/zkvm-elf"),
        //     ledger_db.clone(),
        // );

        let zk_stf = StfBlueprint::new();
        let zk_storage = ZkStorage::new();

        let proof_mode = match proving_mode {
            ProverGuestRunConfig::Skip => ProofGenMode::Skip,
            ProverGuestRunConfig::Simulate => {
                let stf_verifier = StateTransitionVerifier::new(zk_stf, da_verifier);
                ProofGenMode::Simulate(stf_verifier)
            }
            ProverGuestRunConfig::Execute => ProofGenMode::Execute,
            ProverGuestRunConfig::Prove => ProofGenMode::Prove,
        };

        ParallelProverService::new_from_env(
            da_service.clone(),
            vm,
            proof_mode,
            zk_storage,
            ledger_db,
        )
        .expect("Should be able to instantiate prover service")
    }
}
