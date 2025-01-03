use std::sync::Arc;

use async_trait::async_trait;
use futures::future;
use rand::Rng;
use sov_db::ledger_db::LedgerDB;
use sov_rollup_interface::da::DaTxRequest;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use sov_stf_runner::{ProofData, ProverService};
use tokio::sync::{oneshot, Mutex};
use tracing::{info, warn};

use crate::ProofGenMode;

/// Prover service that generates proofs in parallel.
pub struct ParallelProverService<Da, Vm>
where
    Da: DaService,
    Vm: ZkvmHost + 'static,
{
    thread_pool: rayon::ThreadPool,

    proof_mode: ProofGenMode,

    da_service: Arc<Da>,
    vm: Vm,
    _ledger_db: LedgerDB,

    proof_queue: Arc<Mutex<Vec<ProofData>>>,
}

impl<Da, Vm> ParallelProverService<Da, Vm>
where
    Da: DaService,
    Vm: ZkvmHost,
{
    /// Creates a new prover.
    pub fn new(
        da_service: Arc<Da>,
        vm: Vm,
        proof_mode: ProofGenMode,
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
            ProofGenMode::Execute => {
                tracing::info!("Prover is configured to execute proving");
            }
            ProofGenMode::ProveWithSampling => {
                tracing::info!("Prover is configured to prove");
            }
            ProofGenMode::ProveWithSamplingWithFakeProofs(proof_sampling_number) => {
                if proof_sampling_number == 0 {
                    tracing::info!("Prover is configured to always prove");
                } else {
                    tracing::info!(
                        "Prover is configured to prove with fake proofs with 1/{proof_sampling_number} sampling"
                    );
                }
            }
        };

        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_pool_size)
            .build()
            .expect("Thread pool must be built");

        Ok(Self {
            thread_pool,
            proof_mode,
            da_service,
            vm,
            _ledger_db,
            proof_queue: Arc::new(Mutex::new(vec![])),
        })
    }

    /// Creates a new `ParallelProverService` with thread_pool_size retrieved from
    /// environment variable `PARALLEL_PROOF_LIMIT`. If non-existent, will panic.
    pub fn new_from_env(
        da_service: Arc<Da>,
        vm: Vm,
        proof_mode: ProofGenMode,
        _ledger_db: LedgerDB,
    ) -> anyhow::Result<Self> {
        let thread_pool_size = std::env::var("PARALLEL_PROOF_LIMIT")
            .expect("PARALLEL_PROOF_LIMIT must be set")
            .parse::<usize>()
            .expect("PARALLEL_PROOF_LIMIT must be valid unsigned number");

        Self::new(da_service, vm, proof_mode, thread_pool_size, _ledger_db)
    }

    async fn prove_all(&self, proof_queue: Vec<ProofData>) -> Vec<Proof> {
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
            let proof_fut = self.prove_one(proof_data);
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

    async fn prove_one(
        &self,
        ProofData {
            input,
            assumptions,
            elf,
        }: ProofData,
    ) -> Proof {
        let mut vm = self.vm.clone();
        let proof_mode = self.proof_mode;

        vm.add_hint(input);
        for assumption in assumptions {
            vm.add_assumption(assumption);
        }

        let (tx, rx) = oneshot::channel();
        self.thread_pool.spawn(move || {
            let proof = make_proof(vm, elf, proof_mode).expect("Proof creation must not fail");
            let _ = tx.send(proof);
        });

        rx.await.expect("Should not have channel errors")
    }

    async fn submit_proof(&self, proof: Proof) -> anyhow::Result<<Da as DaService>::TransactionId> {
        let tx_request = DaTxRequest::ZKProof(proof);
        self.da_service
            .send_transaction(tx_request)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[async_trait]
impl<Da, Vm> ProverService for ParallelProverService<Da, Vm>
where
    Da: DaService,
    Vm: ZkvmHost,
{
    type DaService = Da;

    async fn add_proof_data(&self, proof_data: ProofData) {
        let mut proof_queue = self.proof_queue.lock().await;
        proof_queue.push(proof_data);
    }

    async fn prove(&self) -> anyhow::Result<Vec<Proof>> {
        let mut proof_queue = self.proof_queue.lock().await;
        if let ProofGenMode::Skip = self.proof_mode {
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
        Ok(self.prove_all(proof_queue).await)
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

fn make_proof<Vm>(
    mut vm: Vm,
    elf: Vec<u8>,
    proof_mode: ProofGenMode,
) -> Result<Proof, anyhow::Error>
where
    Vm: ZkvmHost,
{
    match proof_mode {
        ProofGenMode::Skip => Ok(Vec::default()),
        ProofGenMode::Execute => vm.run(elf, false),
        ProofGenMode::ProveWithSampling => {
            // `make_proof` is called with a probability in this case.
            // When it's called, we have to produce a real proof.
            vm.run(elf, true)
        }
        ProofGenMode::ProveWithSamplingWithFakeProofs(proof_sampling_number) => {
            // `make_proof` is called unconditionally in this case.
            // When it's called, we have to calculate the probabiliry for a proof
            //  and produce a real proof if we are lucky. If unlucky - produce a fake proof.
            let with_prove = proof_sampling_number == 0
                || rand::thread_rng().gen_range(0..proof_sampling_number) == 0;
            vm.run(elf, with_prove)
        }
    }
}
