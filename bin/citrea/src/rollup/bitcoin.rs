use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin_da::rpc::create_rpc_module as create_da_rpc_module;
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig, TxidWrapper};
use bitcoin_da::spec::{BitcoinSpec, RollupParams};
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_common::rpc::register_healthcheck_rpc;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::{BatchProverConfig, FullNodeConfig, LightClientProverConfig};
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use citrea_risc0_adapter::host::Risc0BonsaiHost;
use citrea_risc0_adapter::Digest;
// use citrea_sp1::host::SP1Host;
use citrea_stf::genesis_config::StorageConfig;
use citrea_stf::runtime::Runtime;
use citrea_stf::verifier::StateTransitionVerifier;
use prover_services::{ParallelProverService, ProofGenMode};
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::{DefaultContext, ZkDefaultContext};
use sov_modules_api::{Address, Spec};
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::services::da::SenderWithNotifier;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::{Zkvm, ZkvmHost};
use sov_state::ZkStorage;
use sov_stf_runner::ProverGuestRunConfig;
use tokio::sync::broadcast;
use tokio::sync::mpsc::unbounded_channel;
use tracing::instrument;

use crate::CitreaRollupBlueprint;

/// Rollup with BitcoinDa
pub struct BitcoinRollup {}

impl CitreaRollupBlueprint for BitcoinRollup {}

#[async_trait]
impl RollupBlueprint for BitcoinRollup {
    type DaService = BitcoinService;
    type DaSpec = BitcoinSpec;
    type DaConfig = BitcoinServiceConfig;
    type Vm = Risc0BonsaiHost<'static>;
    type ZkContext = ZkDefaultContext;
    type NativeContext = DefaultContext;

    type StorageManager = ProverStorageManager<BitcoinSpec>;

    type ZkRuntime = Runtime<Self::ZkContext, Self::DaSpec>;
    type NativeRuntime = Runtime<Self::NativeContext, Self::DaSpec>;

    type ProverService = ParallelProverService<
        Self::DaService,
        Self::Vm,
        StfBlueprint<Self::ZkContext, Self::DaSpec, <Self::Vm as ZkvmHost>::Guest, Self::ZkRuntime>,
    >;

    fn new() -> Self {
        Self {}
    }

    #[instrument(level = "trace", skip_all, err)]
    fn create_rpc_methods(
        &self,
        storage: &<Self::NativeContext as Spec>::Storage,
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

    #[instrument(level = "trace", skip(self), ret)]
    fn get_batch_prover_code_commitments_by_spec(
        &self,
    ) -> HashMap<SpecId, <Self::Vm as Zkvm>::CodeCommitment> {
        let mut map = HashMap::new();
        map.insert(
            SpecId::Genesis,
            Digest::new(citrea_risc0::BATCH_PROOF_BITCOIN_ID),
        );
        // let (_, vk) = citrea_sp1::host::CLIENT.setup(include_bytes!("../../provers/sp1/batch-prover-bitcoin/elf/zkvm-elf"));
        // map.insert(SpecId::Genesis, vk);
        map
    }

    #[instrument(level = "trace", skip(self), ret)]
    fn get_light_client_prover_code_commitment(&self) -> <Self::Vm as Zkvm>::CodeCommitment {
        Digest::new(citrea_risc0::LIGHT_CLIENT_PROOF_BITCOIN_ID)
    }

    #[instrument(level = "trace", skip_all, err)]
    fn create_storage_manager(
        &self,
        rollup_config: &citrea_common::FullNodeConfig<Self::DaConfig>,
    ) -> Result<Self::StorageManager, anyhow::Error> {
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

    #[instrument(level = "trace", skip_all)]
    async fn create_batch_prover_service(
        &self,
        prover_config: BatchProverConfig,
        _rollup_config: &FullNodeConfig<Self::DaConfig>,
        da_service: &Arc<Self::DaService>,
        ledger_db: LedgerDB,
    ) -> Self::ProverService {
        let vm = Risc0BonsaiHost::new(citrea_risc0::BATCH_PROOF_BITCOIN_ELF, ledger_db.clone());
        // let vm = SP1Host::new(
        //     include_bytes!("../../provers/sp1/batch-prover-bitcoin/elf/zkvm-elf"),
        //     ledger_db.clone(),
        // );

        let zk_stf = StfBlueprint::new();
        let zk_storage = ZkStorage::new();

        let da_verifier = BitcoinVerifier::new(RollupParams {
            to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
            to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
        });

        let proof_mode = match prover_config.proving_mode {
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

    #[instrument(level = "trace", skip_all)]
    async fn create_light_client_prover_service(
        &self,
        prover_config: LightClientProverConfig,
        _rollup_config: &FullNodeConfig<Self::DaConfig>,
        da_service: &Arc<Self::DaService>,
        ledger_db: LedgerDB,
    ) -> Self::ProverService {
        let vm = Risc0BonsaiHost::new(
            citrea_risc0::LIGHT_CLIENT_PROOF_BITCOIN_ELF,
            ledger_db.clone(),
        );
        let zk_stf = StfBlueprint::new();
        let zk_storage = ZkStorage::new();

        let da_verifier = BitcoinVerifier::new(RollupParams {
            to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
            to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
        });

        let proof_mode = match prover_config.proving_mode {
            ProverGuestRunConfig::Skip => ProofGenMode::Skip,
            ProverGuestRunConfig::Simulate => {
                let stf_verifier = StateTransitionVerifier::new(zk_stf, da_verifier);
                ProofGenMode::Simulate(stf_verifier)
            }
            ProverGuestRunConfig::Execute => ProofGenMode::Execute,
            ProverGuestRunConfig::Prove => ProofGenMode::Prove,
        };

        ParallelProverService::new(da_service.clone(), vm, proof_mode, zk_storage, 1, ledger_db)
            .expect("Should be able to instantiate prover service")
    }
}
