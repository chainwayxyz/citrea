mod prover;
use std::sync::Arc;

use async_trait::async_trait;
use borsh::BorshDeserialize;
use citrea_stf::verifier::StateTransitionVerifier;
use parking_lot::Mutex;
use prover::Prover;
use risc0_zkvm::{Journal, Receipt};
use sov_db::ledger_db::{LedgerDB, ProvingServiceLedgerOps};
use sov_rollup_interface::da::{DaData, DaSpec};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use sov_stf_runner::{
    ProofProcessingStatus, ProverGuestRunConfig, ProverService, ProverServiceError,
    WitnessSubmissionStatus,
};

use self::prover::ProverStatus;
use crate::ProofGenConfig;

/// Prover service that generates proofs in parallel.
pub struct ParallelProverService<Da, Vm, V>
where
    Da: DaService,
    Vm: ZkvmHost,
    V: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync,
{
    vm: Vm,
    prover_config: Arc<Mutex<ProofGenConfig<V, Da, Vm>>>,

    zk_storage: V::PreState,
    prover_state: Prover<Da>,
    ledger_db: LedgerDB,
}

impl<Da, Vm, V> ParallelProverService<Da, Vm, V>
where
    Da: DaService,
    Vm: ZkvmHost,
    V: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync,
    V::PreState: Clone + Send + Sync,
{
    /// Creates a new prover.
    pub fn new(
        vm: Vm,
        zk_stf: V,
        da_verifier: Da::Verifier,
        config: ProverGuestRunConfig,
        zk_storage: V::PreState,
        num_threads: usize,
        ledger_db: LedgerDB,
    ) -> anyhow::Result<Self> {
        let stf_verifier =
            StateTransitionVerifier::<V, Da::Verifier, Vm::Guest>::new(zk_stf, da_verifier);

        let config: ProofGenConfig<V, Da, Vm> = match config {
            ProverGuestRunConfig::Skip => ProofGenConfig::Skip,
            ProverGuestRunConfig::Simulate => ProofGenConfig::Simulate(stf_verifier),
            ProverGuestRunConfig::Execute => ProofGenConfig::Execute,
            ProverGuestRunConfig::Prove => ProofGenConfig::Prover,
        };

        // output config
        match config {
            ProofGenConfig::Skip => {
                tracing::info!("Prover is configured to skip proving");
            }
            ProofGenConfig::Simulate(_) => {
                tracing::info!("Prover is configured to simulate proving");
            }
            ProofGenConfig::Execute => {
                tracing::info!("Prover is configured to execute proving");
            }
            ProofGenConfig::Prover => {
                tracing::info!("Prover is configured to prove");
            }
        }

        let prover_config = Arc::new(Mutex::new(config));

        Ok(Self {
            vm,
            prover_config,
            prover_state: Prover::new(num_threads)?,
            zk_storage,
            ledger_db,
        })
    }

    /// Creates a new prover.
    pub fn new_with_default_workers(
        vm: Vm,
        zk_stf: V,
        da_verifier: Da::Verifier,
        proving_mode: ProverGuestRunConfig,
        zk_storage: V::PreState,
        ledger_db: LedgerDB,
    ) -> anyhow::Result<Self> {
        let num_cpus = num_cpus::get();
        assert!(num_cpus > 1, "Unable to create parallel prover service");

        Self::new(
            vm,
            zk_stf,
            da_verifier,
            proving_mode,
            zk_storage,
            num_cpus - 1,
            ledger_db,
        )
    }
}

#[async_trait]
impl<Da, Vm, V> ProverService<Vm> for ParallelProverService<Da, Vm, V>
where
    Da: DaService,
    Vm: ZkvmHost + 'static,
    V: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync + 'static,
    V::PreState: Clone + Send + Sync,
{
    type DaService = Da;

    async fn submit_witness(
        &self,
        input: Vec<u8>,
        da_slot_hash: <Da::Spec as DaSpec>::SlotHash,
    ) -> WitnessSubmissionStatus {
        self.prover_state.submit_witness(input, da_slot_hash)
    }

    async fn prove(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
    ) -> Result<ProofProcessingStatus, ProverServiceError> {
        let vm = self.vm.clone();
        let zk_storage = self.zk_storage.clone();

        tracing::info!("Starting proving for da  block: {:?},", block_header_hash,);
        self.prover_state.start_proving(
            block_header_hash,
            self.prover_config.clone(),
            vm,
            zk_storage,
        )
    }

    async fn wait_for_proving_and_extract_output<T: BorshDeserialize>(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
    ) -> Result<T, anyhow::Error> {
        let proof = self.wait_for_proof(block_header_hash).await?;

        // TODO: maybe extract this to Vm?
        // Extract journal
        let journal = match proof {
            Proof::PublicInput(journal) => {
                let journal: Journal = bincode::deserialize(&journal)?;
                journal
            }
            Proof::Full(data) => {
                let receipt: Receipt = bincode::deserialize(&data)?;
                receipt.journal
            }
        };

        self.ledger_db.clear_pending_proving_sessions()?;

        Ok(T::try_from_slice(&journal.bytes)?)
    }

    async fn wait_for_proving_and_send_to_da(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
        da_service: &Arc<Self::DaService>,
    ) -> Result<(<Da as DaService>::TransactionId, Proof), anyhow::Error> {
        let proof = self.wait_for_proof(block_header_hash).await?;
        let da_data = DaData::ZKProof(proof.clone());

        let tx_id = da_service
            .send_transaction(da_data)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        self.ledger_db.clear_pending_proving_sessions()?;

        Ok((tx_id, proof))
    }

    async fn recover_proving_sessions_and_send_to_da(
        &self,
        da_service: &Arc<Self::DaService>,
    ) -> Result<Vec<(<Da as DaService>::TransactionId, Proof)>, anyhow::Error> {
        tracing::debug!("Checking if ongoing bonsai session exists");

        let vm = self.vm.clone();
        let proofs = vm.recover_proving_sessions()?;

        let mut results = Vec::new();

        for proof in proofs.into_iter() {
            let da_data = DaData::ZKProof(proof.clone());
            let tx_id = da_service
                .send_transaction(da_data)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            results.push((tx_id, proof));
        }
        self.ledger_db.clear_pending_proving_sessions()?;
        Ok(results)
    }
}

impl<Da, Vm, V> ParallelProverService<Da, Vm, V>
where
    Da: DaService,
    Vm: ZkvmHost + 'static,
    V: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync + 'static,
    V::PreState: Clone + Send + Sync,
{
    async fn wait_for_proof(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
    ) -> anyhow::Result<Proof> {
        loop {
            let status = self
                .prover_state
                .get_prover_status_for_da_submission(block_header_hash.clone())?;

            match status {
                ProverStatus::Proved(proof) => break Ok(proof),
                ProverStatus::ProvingInProgress => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                _ => {
                    // function will not return any other type of status
                }
            }
        }
    }
}
