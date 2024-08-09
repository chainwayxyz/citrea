mod prover;
use std::sync::Arc;

use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use citrea_stf::verifier::StateTransitionVerifier;
use prover::Prover;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_rollup_interface::da::{DaData, DaSpec};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::{Proof, StateTransitionData, ZkvmHost};
use sov_stf_runner::config::ProverConfig;
use sov_stf_runner::{
    ProofProcessingStatus, ProverGuestRunConfig, ProverService, ProverServiceError,
    WitnessSubmissionStatus,
};

use self::prover::ProverStatus;
use crate::prover_service::ProofGenConfig;

/// Prover service that generates proofs in parallel.
pub struct ParallelProverService<StateRoot, Witness, Da, Vm, V>
where
    StateRoot: Serialize + DeserializeOwned + Clone + AsRef<[u8]>,
    Witness: Serialize + DeserializeOwned,
    Da: DaService,
    Vm: ZkvmHost,
    V: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync,
{
    vm: Vm,
    prover_config: Arc<ProofGenConfig<V, Da, Vm>>,

    zk_storage: V::PreState,
    prover_state: Prover<StateRoot, Witness, Da>,
}

impl<StateRoot, Witness, Da, Vm, V> ParallelProverService<StateRoot, Witness, Da, Vm, V>
where
    StateRoot: BorshSerialize
        + BorshDeserialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Send
        + Sync
        + 'static,
    Witness:
        BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned + Send + Sync + 'static,
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

        let prover_config = Arc::new(config);

        Ok(Self {
            vm,
            prover_config,
            prover_state: Prover::new(num_threads)?,
            zk_storage,
        })
    }

    /// Creates a new prover.
    pub fn new_with_default_workers(
        vm: Vm,
        zk_stf: V,
        da_verifier: Da::Verifier,
        prover_config: ProverConfig,
        zk_storage: V::PreState,
    ) -> anyhow::Result<Self> {
        let num_cpus = num_cpus::get();
        assert!(num_cpus > 1, "Unable to create parallel prover service");

        Self::new(
            vm,
            zk_stf,
            da_verifier,
            prover_config.proving_mode,
            zk_storage,
            num_cpus - 1,
        )
    }
}

#[async_trait]
impl<StateRoot, Witness, Da, Vm, V> ProverService<Vm>
    for ParallelProverService<StateRoot, Witness, Da, Vm, V>
where
    StateRoot: BorshSerialize
        + BorshDeserialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Send
        + Sync
        + 'static,
    Witness:
        BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned + Send + Sync + 'static,
    Da: DaService,
    Vm: ZkvmHost + 'static,
    V: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync + 'static,
    V::PreState: Clone + Send + Sync,
{
    type StateRoot = StateRoot;

    type Witness = Witness;

    type DaService = Da;

    async fn submit_witness(
        &self,
        state_transition_data: StateTransitionData<
            Self::StateRoot,
            Self::Witness,
            <Self::DaService as DaService>::Spec,
        >,
    ) -> WitnessSubmissionStatus {
        self.prover_state.submit_witness(state_transition_data)
    }

    async fn prove(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
        l1_block_height: u64,
    ) -> Result<ProofProcessingStatus, ProverServiceError> {
        let vm = self.vm.clone();
        let zk_storage = self.zk_storage.clone();

        tracing::info!("Starting proving for da  block: {:?},", block_header_hash,);
        self.prover_state.start_proving(
            block_header_hash,
            l1_block_height,
            self.prover_config.clone(),
            vm,
            zk_storage,
        )
    }

    async fn wait_for_proving_and_send_to_da(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
        da_service: &Arc<Self::DaService>,
    ) -> Result<(<Da as DaService>::TransactionId, Proof), anyhow::Error> {
        loop {
            let status = self
                .prover_state
                .get_prover_status_for_da_submission(block_header_hash.clone())?;

            match status {
                ProverStatus::Proved(proof) => {
                    let da_data = DaData::ZKProof(proof.clone());

                    let tx_id = da_service
                        .send_transaction(
                            borsh::to_vec(&da_data)
                                .expect("Should serialize")
                                .as_slice(),
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!(e))?;
                    break Ok((tx_id, proof));
                }
                ProverStatus::ProvingInProgress => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                _ => {
                    // function will not return any other type of status
                }
            }
        }
    }

    async fn recover_proving_and_send_to_da(
        &self,
        stark_id: Option<String>,
        snark_id: Option<String>,
        da_service: &Self::DaService,
        l1_block_height: u64,
    ) -> Result<Option<(<Da as DaService>::TransactionId, Proof)>, anyhow::Error> {
        let vm = self.vm.clone();

        tracing::info!("Checking if ongoing bonsai session exists");

        match snark_id {
            Some(snark_id) => {
                tracing::warn!(
                    "There is an ongoing stark to snark conversion, waiting for it to complete"
                );
                // Stark id is present, prover crashed at an ongoing stark to snark conversion
                let stark_id = stark_id.expect("Stark id should be present");
                // Get receipt from stark
                let receipt_buf = vm.wait_for_receipt(&stark_id.clone())?;
                // wait for the stark to snark conversion to complete
                let proof =
                    vm.wait_for_stark_to_snark_conversion(&snark_id, receipt_buf, l1_block_height)?;
                // Send to da
                let da_data = DaData::ZKProof(proof.clone());
                let tx_id = da_service
                    .send_transaction(
                        borsh::to_vec(&da_data)
                            .expect("Should serialize")
                            .as_slice(),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
                Ok(Some((tx_id, proof)))
            }
            None => {
                match stark_id {
                    Some(stark_id) => {
                        tracing::warn!("There is an ongoing stark proof generation, waiting for it to complete");
                        // Only stark id is present, prover crashed at receipt generation
                        // wait for the stark proof generation to complete
                        let receipt_buf = vm.wait_for_receipt(&stark_id)?;
                        // Create new snark session
                        let snark_uuid = vm.create_new_snark_session(&stark_id)?;
                        // wait for the stark to snark conversion to complete
                        let proof = vm.wait_for_stark_to_snark_conversion(
                            &snark_uuid,
                            receipt_buf,
                            l1_block_height,
                        )?;

                        let da_data = DaData::ZKProof(proof.clone());
                        // Send to da
                        let tx_id = da_service
                            .send_transaction(
                                borsh::to_vec(&da_data)
                                    .expect("Should serialize")
                                    .as_slice(),
                            )
                            .await
                            .map_err(|e| anyhow::anyhow!(e))?;
                        Ok(Some((tx_id, proof)))
                    }
                    None => {
                        // No stark id, no snark id, prover has not crashed
                        tracing::info!("Prover has no existing ongoing bonsai session");
                        Ok(None)
                    }
                }
            }
        }
    }
}
