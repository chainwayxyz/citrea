use std::ops::DerefMut;
use std::sync::Arc;

use async_trait::async_trait;
use borsh::BorshDeserialize;
use citrea_stf::verifier::StateTransitionVerifier;
use futures::{future, SinkExt};
use parking_lot::Mutex;
use risc0_zkvm::Receipt;
use sov_db::ledger_db::{LedgerDB, ProvingServiceLedgerOps};
use sov_rollup_interface::da::{DaData, DaSpec};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use sov_stf_runner::{
    ProofProcessingStatus, ProverGuestRunConfig, ProverService, ProverServiceError,
    WitnessSubmissionStatus,
};
use tokio::sync::oneshot;

use crate::{ProofGenConfig, ProofGenMode};

pub(crate) type Input = Vec<u8>;
pub(crate) type Assumptions = Vec<Vec<u8>>;
pub(crate) type ProofData = (Input, Assumptions);

/// Prover service that generates proofs in parallel.
pub struct ParallelProverService<Da, Vm, Stf>
where
    Da: DaService,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync,
    Stf::PreState: Clone + Send + Sync,
{
    thread_pool: rayon::ThreadPool,

    proof_mode: Arc<Mutex<ProofGenMode<Da, Vm, Stf>>>,

    da_service: Da,
    vm: Vm,
    zk_storage: Stf::PreState,
    ledger_db: LedgerDB,

    current_da_hash: Option<<Da::Spec as DaSpec>::SlotHash>,
    proof_queue: Vec<ProofData>,
}

impl<Da, Vm, Stf> ParallelProverService<Da, Vm, Stf>
where
    Da: DaService,
    Vm: ZkvmHost + 'static,
    Stf: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync + 'static,
    Stf::PreState: Clone + Send + Sync,
{
    /// Creates a new prover.
    pub fn new(
        da_service: Da,
        vm: Vm,
        proof_mode: ProofGenMode<Da, Vm, Stf>,
        zk_storage: Stf::PreState,
        thread_pool_size: usize,
        ledger_db: LedgerDB,
    ) -> anyhow::Result<Self> {
        match proof_mode {
            ProofGenMode::Skip => {
                tracing::info!("Prover is configured to skip proving");
            }
            ProofGenMode::Simulate(_) => {
                tracing::info!("Prover is configured to simulate proving");
            }
            ProofGenMode::Execute => {
                tracing::info!("Prover is configured to execute proving");
            }
            ProofGenMode::Prove => {
                tracing::info!("Prover is configured to prove");
            }
        };

        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_pool_size)
            .build()
            .expect("Thread pool must be built");

        Ok(Self {
            thread_pool,
            proof_mode: Arc::new(Mutex::new(proof_mode)),
            da_service,
            vm,
            zk_storage,
            ledger_db,
            current_da_hash: None,
            proof_queue: vec![],
        })
    }

    /// Creates a new `ParallelProverService` with the default number of thread pool size.
    /// Default thread pool size is num_cpus - 1.
    pub fn new_with_default_workers(
        da_service: Da,
        vm: Vm,
        proof_mode: ProofGenMode<Da, Vm, Stf>,
        zk_storage: Stf::PreState,
        ledger_db: LedgerDB,
    ) -> anyhow::Result<Self> {
        let num_cpus = num_cpus::get();
        assert!(
            num_cpus > 1,
            "Parallel prover service requires at least 2 available cores to run smoothly"
        );

        Self::new(
            da_service,
            vm,
            proof_mode,
            zk_storage,
            num_cpus - 1,
            ledger_db,
        )
    }

    pub fn set_current_da_hash(&mut self, da_hash: <Da::Spec as DaSpec>::SlotHash) {
        assert!(
            self.current_da_hash.is_none(),
            "Da hash to prove should never be set twice"
        );
        self.current_da_hash = Some(da_hash);
    }

    pub fn add_proof_data(&mut self, proof_data: ProofData) {
        assert!(
            self.current_da_hash.is_some(),
            "Add proof data should never be called before setting da hash"
        );
        self.proof_queue.push(proof_data);
    }

    pub async fn prove_and_submit(&mut self) -> anyhow::Result<Vec<<Da as DaService>::TransactionId>> {
        if let ProofGenMode::Skip = *self.proof_mode.lock() {
            tracing::debug!(
                "Skipped proving {} proofs in block {:?}",
                self.proof_queue.len(),
                self.current_da_hash
            );

            self.current_da_hash = None;
            self.proof_queue.clear();

            return Ok(vec![]);
        }

        assert!(
            !self.proof_queue.is_empty(),
            "Prove should never be called before setting some proofs"
        );

        let proof_queue = std::mem::take(&mut self.proof_queue);
        // Prove all
        let proofs = self.prove(proof_queue).await;

        // Submit proofs to DA
        let mut tx_ids = vec![];
        for proof in proofs {
            let tx_id = self.submit_proof(proof).await?;
            tx_ids.push(tx_id);
        }

        self.current_da_hash = None;

        Ok(tx_ids)
    }

    async fn prove(&mut self, proof_queue: Vec<ProofData>) -> Vec<Proof> {
        let mut rxs = Vec::with_capacity(proof_queue.len());
        // Initialize proof workers
        for proof_data in proof_queue {
            let rx = self.prove_with(proof_data);
            rxs.push(rx);
        }

        // Wait for all proofs to be completed
        future::try_join_all(rxs)
            .await
            .expect("Should not have channel errors")
    }

    fn prove_with(&self, (input, assumptions): ProofData) -> oneshot::Receiver<Vec<u8>> {
        let mut vm = self.vm.clone();
        let zk_storage = self.zk_storage.clone();
        let proof_mode = self.proof_mode.clone();

        vm.add_hint(input);
        for assumption in assumptions {
            vm.add_assumption(assumption);
        }

        let (tx, rx) = oneshot::channel();
        self.thread_pool.spawn(move || {
            let proof =
                make_proof(vm, zk_storage, proof_mode).expect("Proof creation must not fail");
            let _ = tx.send(proof);
        });

        rx
    }

    async fn submit_proof(
        &self,
        proof: Proof,
    ) -> anyhow::Result<<Da as DaService>::TransactionId> {
        let da_data = DaData::ZKProof(proof);
        self.da_service
            .send_transaction(da_data)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }
}

fn make_proof<Da, Vm, Stf>(
    mut vm: Vm,
    zk_storage: Stf::PreState,
    proof_mode: Arc<Mutex<ProofGenMode<Da, Vm, Stf>>>,
) -> Result<Proof, anyhow::Error>
where
    Da: DaService,
    Vm: ZkvmHost + 'static,
    Stf: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync + 'static,
    Stf::PreState: Send + Sync + 'static,
{
    let mut proof_mode = proof_mode.lock();
    match proof_mode.deref_mut() {
        ProofGenMode::Skip => Ok(Vec::default()),
        ProofGenMode::Simulate(ref mut verifier) => verifier
            .run_sequencer_commitments_in_da_slot(vm.simulate_with_hints(), zk_storage)
            .map(|_| Vec::default())
            .map_err(|e| anyhow::anyhow!("Guest execution must succeed but failed with {:?}", e)),
        ProofGenMode::Execute => vm.run(false),
        ProofGenMode::Prove => vm.run(true),
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

    async fn submit_assumptions(
        &self,
        assumptions: Vec<Vec<u8>>,
        da_slot_hash: <Da::Spec as DaSpec>::SlotHash,
    ) {
        todo!()
    }

    async fn submit_input(
        &self,
        input: Vec<u8>,
        da_slot_hash: <Da::Spec as DaSpec>::SlotHash,
    ) -> WitnessSubmissionStatus {
        todo!()
    }

    async fn prove(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
    ) -> Result<ProofProcessingStatus, ProverServiceError> {
        todo!()
    }

    async fn wait_for_proving_and_extract_output<T: BorshDeserialize>(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
    ) -> Result<T, anyhow::Error> {
        todo!()
    }

    async fn wait_for_proving_and_send_to_da(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
        da_service: &Arc<Self::DaService>,
    ) -> Result<(<Da as DaService>::TransactionId, Proof), anyhow::Error> {
        todo!()
    }

    async fn recover_proving_sessions_and_send_to_da(
        &self,
        da_service: &Arc<Self::DaService>,
    ) -> Result<Vec<(<Da as DaService>::TransactionId, Proof)>, anyhow::Error> {
        todo!()
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
        todo!()
    }
}
