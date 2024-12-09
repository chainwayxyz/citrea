use std::ops::DerefMut;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future;
use sov_db::ledger_db::LedgerDB;
use sov_rollup_interface::da::DaData;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use sov_stf_runner::ProverService;
use tokio::sync::{oneshot, Mutex};
use tracing::{info, warn};

use crate::ProofGenMode;

pub(crate) type Input = Vec<u8>;
pub(crate) type Assumptions = Vec<Vec<u8>>;
pub(crate) type ProofData = (Input, Assumptions);

/// Prover service that generates proofs in parallel.
pub struct ParallelProverService<Da, Vm, Stf>
where
    Da: DaService,
    Vm: ZkvmHost + 'static,
    Stf: StateTransitionFunction<Da::Spec> + Send + Sync + 'static,
    Stf::PreState: Clone + Send + Sync + 'static,
{
    thread_pool: rayon::ThreadPool,

    proof_mode: Arc<Mutex<ProofGenMode<Da, Vm, Stf>>>,

    da_service: Arc<Da>,
    vm: Vm,
    zk_storage: Stf::PreState,
    _ledger_db: LedgerDB,

    proof_queue: Arc<Mutex<Vec<ProofData>>>,
}

impl<Da, Vm, Stf> ParallelProverService<Da, Vm, Stf>
where
    Da: DaService,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Da::Spec> + Send + Sync,
    Stf::PreState: Clone + Send + Sync,
{
    /// Creates a new prover.
    pub fn new(
        da_service: Arc<Da>,
        vm: Vm,
        proof_mode: ProofGenMode<Da, Vm, Stf>,
        zk_storage: Stf::PreState,
        thread_pool_size: usize,
        _ledger_db: LedgerDB,
    ) -> anyhow::Result<Self> {
        assert!(
            thread_pool_size > 0,
            "Prover thread pool size must be greater than 1"
        );

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
            _ledger_db,
            proof_queue: Arc::new(Mutex::new(vec![])),
        })
    }

    /// Creates a new `ParallelProverService` with thread_pool_size retrieved from
    /// environment variable `PARALLEL_PROOF_LIMIT`. If non-existent, will panic.
    pub fn new_from_env(
        da_service: Arc<Da>,
        vm: Vm,
        proof_mode: ProofGenMode<Da, Vm, Stf>,
        zk_storage: Stf::PreState,
        _ledger_db: LedgerDB,
    ) -> anyhow::Result<Self> {
        let thread_pool_size = std::env::var("PARALLEL_PROOF_LIMIT")
            .expect("PARALLEL_PROOF_LIMIT must be set")
            .parse::<usize>()
            .expect("PARALLEL_PROOF_LIMIT must be valid unsigned number");

        Self::new(
            da_service,
            vm,
            proof_mode,
            zk_storage,
            thread_pool_size,
            _ledger_db,
        )
    }

    async fn prove_all(&self, elf: Vec<u8>, proof_queue: Vec<ProofData>) -> Vec<Proof> {
        let num_threads = self.thread_pool.current_num_threads();
        info!(
            "Starting parallel proving of {} proofs with {} workers",
            proof_queue.len(),
            num_threads
        );

        // Future buffer to keep track of ongoing provings
        let mut ongoing_proofs = Vec::with_capacity(num_threads);
        let mut proofs = vec![Proof::default(); proof_queue.len()];
        // Initialize proof workers
        for (idx, proof_data) in proof_queue.into_iter().enumerate() {
            if ongoing_proofs.len() == num_threads {
                warn!(
                    "Reached parallel proof limit, waiting for one of the proving tasks to finish"
                );
                // If no available threads, wait for one of the proofs to finish
                let ((idx, proof), _, remaining_proofs) = future::select_all(ongoing_proofs).await;
                proofs[idx] = proof;
                ongoing_proofs = remaining_proofs;
            }

            info!("Starting proving task {}", idx);
            let proof_fut = self.prove_one(elf.clone(), proof_data);
            ongoing_proofs.push(Box::pin(async move {
                let proof = proof_fut.await;

                info!("Finished proving task {}", idx);

                (idx, proof)
            }));
        }

        // Wait for all the remaining proofs to complete
        let remaining_proofs = future::join_all(ongoing_proofs).await;
        for (idx, proof) in remaining_proofs {
            proofs[idx] = proof;
        }

        proofs
    }

    async fn prove_one(&self, elf: Vec<u8>, (input, assumptions): ProofData) -> Proof {
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
                make_proof(vm, elf, zk_storage, proof_mode).expect("Proof creation must not fail");
            let _ = tx.send(proof);
        });

        rx.await.expect("Should not have channel errors")
    }

    async fn submit_proof(&self, proof: Proof) -> anyhow::Result<<Da as DaService>::TransactionId> {
        let da_data = DaData::ZKProof(proof);
        self.da_service
            .send_transaction(da_data)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[async_trait]
impl<Da, Vm, Stf> ProverService for ParallelProverService<Da, Vm, Stf>
where
    Da: DaService,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Da::Spec> + Send + Sync,
    Stf::PreState: Clone + Send + Sync,
{
    type DaService = Da;

    async fn add_proof_data(&self, proof_data: ProofData) {
        let mut proof_queue = self.proof_queue.lock().await;
        proof_queue.push(proof_data);
    }

    async fn prove(&self, elf: Vec<u8>) -> anyhow::Result<Vec<Proof>> {
        let mut proof_queue = self.proof_queue.lock().await;
        if let ProofGenMode::Skip = *self.proof_mode.lock().await {
            tracing::debug!("Skipped proving {} proofs", proof_queue.len());
            proof_queue.clear();
            return Ok(vec![]);
        }

        assert!(
            !proof_queue.is_empty(),
            "Prove should never be called before setting some proofs"
        );

        // Clear current proof data
        let proof_queue = std::mem::take(&mut *proof_queue);

        // Prove all
        Ok(self.prove_all(elf, proof_queue).await)
    }

    async fn submit_proofs(
        &self,
        proofs: Vec<Proof>,
    ) -> anyhow::Result<Vec<(<Da as DaService>::TransactionId, Proof)>> {
        let mut tx_and_proof = Vec::with_capacity(proofs.len());
        for proof in proofs {
            let tx_id = self.submit_proof(proof.clone()).await?;
            tx_and_proof.push((tx_id, proof));
        }
        Ok(tx_and_proof)
    }

    async fn recover_and_submit_proving_sessions(
        &self,
    ) -> anyhow::Result<Vec<(<Da as DaService>::TransactionId, Proof)>> {
        let vm = self.vm.clone();
        let proofs = vm.recover_proving_sessions()?;

        self.submit_proofs(proofs).await
    }
}

fn make_proof<Da, Vm, Stf>(
    mut vm: Vm,
    elf: Vec<u8>,
    zk_storage: Stf::PreState,
    proof_mode: Arc<Mutex<ProofGenMode<Da, Vm, Stf>>>,
) -> Result<Proof, anyhow::Error>
where
    Da: DaService,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Da::Spec> + Send + Sync,
    Stf::PreState: Send + Sync,
{
    let mut proof_mode = proof_mode.blocking_lock();
    match proof_mode.deref_mut() {
        ProofGenMode::Skip => Ok(Vec::default()),
        ProofGenMode::Simulate(ref mut verifier) => verifier
            .run_sequencer_commitments_in_da_slot(vm.simulate_with_hints(), zk_storage)
            .map(|_| Vec::default())
            .map_err(|e| anyhow::anyhow!("Guest execution must succeed but failed with {:?}", e)),
        // If not skip or simulate, we have to drop the lock manually to allow parallel proving
        ProofGenMode::Execute => {
            drop(proof_mode);
            vm.run(elf, false)
        }
        ProofGenMode::Prove => {
            drop(proof_mode);
            vm.run(elf, true)
        }
    }
}
