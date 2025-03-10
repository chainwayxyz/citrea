use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin_da::rpc::create_rpc_module as create_da_rpc_module;
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig, TxidWrapper};
use bitcoin_da::spec::{BitcoinSpec, RollupParams};
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_common::backup::{create_backup_rpc_module, BackupManager};
use citrea_common::config::ProverGuestRunConfig;
use citrea_common::rpc::register_healthcheck_rpc;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::FullNodeConfig;
use citrea_primitives::forks::use_network_forks;
use citrea_primitives::REVEAL_TX_PREFIX;
use citrea_risc0_adapter::host::Risc0BonsaiHost;
// use citrea_sp1::host::SP1Host;
use citrea_stf::genesis_config::StorageConfig;
use citrea_stf::runtime::CitreaRuntime;
use prover_services::{ParallelProverService, ProofGenMode};
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{Address, SpecId, Zkvm};
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::services::da::TxRequestWithNotifier;
use sov_state::ProverStorage;
use tokio::sync::broadcast;
use tokio::sync::mpsc::unbounded_channel;
use tracing::instrument;

use crate::guests::{
    BATCH_PROOF_DEVNET_GUESTS, BATCH_PROOF_LATEST_BITCOIN_GUESTS, BATCH_PROOF_MAINNET_GUESTS,
    BATCH_PROOF_REGTEST_BITCOIN_GUESTS, BATCH_PROOF_TESTNET_GUESTS, LIGHT_CLIENT_DEVNET_GUESTS,
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

    fn new(network: Network) -> Self {
        use_network_forks(network);
        Self { network }
    }

    #[instrument(level = "trace", skip_all, err)]
    fn create_rpc_methods(
        &self,
        storage: ProverStorage,
        ledger_db: &LedgerDB,
        da_service: &Arc<Self::DaService>,
        sequencer_client_url: Option<String>,
        l2_block_rx: Option<broadcast::Receiver<u64>>,
        backup_manager: &Arc<BackupManager>,
    ) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error> {
        // unused inside register RPC
        let sov_sequencer = Address::new([0; 32]);

        let mut rpc_methods = sov_modules_rollup_blueprint::register_rpc::<
            Self::DaService,
            CitreaRuntime<DefaultContext, Self::DaSpec>,
        >(storage.clone(), ledger_db, sov_sequencer)?;

        crate::eth::register_ethereum::<Self::DaService>(
            da_service.clone(),
            storage,
            ledger_db.clone(),
            &mut rpc_methods,
            sequencer_client_url,
            l2_block_rx,
        )?;

        register_healthcheck_rpc(&mut rpc_methods, ledger_db.clone())?;

        let backup_methods = create_backup_rpc_module(ledger_db.clone(), backup_manager.clone());
        rpc_methods.merge(backup_methods)?;

        let da_methods = create_da_rpc_module(da_service.clone());
        rpc_methods.merge(da_methods)?;

        Ok(rpc_methods)
    }

    #[instrument(level = "trace", skip_all, err)]
    fn create_storage_manager(
        &self,
        rollup_config: &citrea_common::FullNodeConfig<Self::DaConfig>,
    ) -> Result<ProverStorageManager, anyhow::Error> {
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
        let (tx, rx) = unbounded_channel::<TxRequestWithNotifier<TxidWrapper>>();

        let bitcoin_service = if require_wallet_check {
            BitcoinService::new_with_wallet_check(
                rollup_config.da.clone(),
                RollupParams {
                    reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
                },
                tx,
            )
            .await?
        } else {
            BitcoinService::new_without_wallet_check(
                rollup_config.da.clone(),
                RollupParams {
                    reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
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
            reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
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
            Network::Devnet => BATCH_PROOF_DEVNET_GUESTS
                .iter()
                .map(|(k, (_, code))| (*k, code.clone()))
                .collect(),
            Network::Nightly => BATCH_PROOF_LATEST_BITCOIN_GUESTS
                .iter()
                .map(|(k, (_, code))| (*k, code.clone()))
                .collect(),
            Network::TestNetworkWithForks => BATCH_PROOF_REGTEST_BITCOIN_GUESTS
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
            Network::Devnet => LIGHT_CLIENT_DEVNET_GUESTS
                .iter()
                .map(|(k, (_, code))| (*k, code.clone()))
                .collect(),
            Network::Nightly | Network::TestNetworkWithForks => LIGHT_CLIENT_LATEST_BITCOIN_GUESTS
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
            Network::Devnet => BATCH_PROOF_DEVNET_GUESTS
                .iter()
                .map(|(k, (id, _))| (*k, *id))
                .collect(),
            Network::Nightly => BATCH_PROOF_LATEST_BITCOIN_GUESTS
                .iter()
                .map(|(k, (id, _))| (*k, *id))
                .collect(),
            Network::TestNetworkWithForks => BATCH_PROOF_REGTEST_BITCOIN_GUESTS
                .iter()
                .map(|(k, (id, _))| (*k, *id))
                .collect(),
        }
    }

    fn get_light_client_proof_code_commitments(
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
            Network::Devnet => LIGHT_CLIENT_DEVNET_GUESTS
                .iter()
                .map(|(k, (id, _))| (*k, *id))
                .collect(),
            Network::Nightly | Network::TestNetworkWithForks => LIGHT_CLIENT_LATEST_BITCOIN_GUESTS
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
        ledger_db: LedgerDB,
        proof_sampling_number: usize,
        is_light_client_prover: bool,
    ) -> ParallelProverService<Self::DaService, Self::Vm> {
        let vm = Risc0BonsaiHost::new(ledger_db.clone(), self.network);
        // let vm = SP1Host::new(
        //     include_bytes!("../guests/sp1/batch-prover-bitcoin/elf/zkvm-elf"),
        //     ledger_db.clone(),
        // );

        let proof_mode = match proving_mode {
            ProverGuestRunConfig::Skip => ProofGenMode::Skip,
            ProverGuestRunConfig::Execute => ProofGenMode::Execute,
            ProverGuestRunConfig::Prove => ProofGenMode::ProveWithSampling,
            ProverGuestRunConfig::ProveWithFakeProofs => {
                ProofGenMode::ProveWithSamplingWithFakeProofs(proof_sampling_number)
            }
        };

        if is_light_client_prover {
            // Parallel proof limit should be 1 for light client prover
            ParallelProverService::new(da_service.clone(), vm, proof_mode, 1)
                .expect("Should be able to instantiate prover service")
        } else {
            ParallelProverService::new_from_env(da_service.clone(), vm, proof_mode)
                .expect("Should be able to instantiate prover service")
        }
    }
}
