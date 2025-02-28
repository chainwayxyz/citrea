use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rand::Rng;
use sov_rollup_interface::da::DaTxRequest;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use tokio::sync::{oneshot, Mutex, Notify};
use tracing::{info, warn};

use crate::{ProofData, ProofGenMode};

/// Prover service that generates proofs in parallel.
pub struct ParallelProverService<Da, Vm>
where
    Da: DaService,
    Vm: ZkvmHost + 'static,
{
    parallel_proof_limit: usize,
    ongoing_proof_count: Arc<Mutex<usize>>,
    proof_done_notifier: Arc<Notify>,
    proof_mode: ProofGenMode,
    da_service: Arc<Da>,
    vm: Vm,
    next_id: AtomicUsize,
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
    ) -> anyhow::Result<Self> {
        assert!(
            thread_pool_size > 0,
            "Prover thread pool size must be greater than 0"
        );

        match proof_mode {
            ProofGenMode::Skip => {
                info!("Prover is configured to skip proving");
            }
            ProofGenMode::Execute => {
                info!("Prover is configured to execute proving");
            }
            ProofGenMode::ProveWithSampling => {
                info!("Prover is configured to prove");
            }
            ProofGenMode::ProveWithSamplingWithFakeProofs(proof_sampling_number) => {
                if proof_sampling_number == 0 {
                    info!("Prover is configured to always prove");
                } else {
                    info!(
                        "Prover is configured to prove with fake proofs with 1/{proof_sampling_number} sampling"
                    );
                }
            }
        };

        Ok(Self {
            parallel_proof_limit: thread_pool_size,
            ongoing_proof_count: Default::default(),
            proof_done_notifier: Default::default(),
            proof_mode,
            da_service,
            vm,
            next_id: Default::default(),
        })
    }

    /// Creates a new `ParallelProverService` with thread_pool_size retrieved from
    /// environment variable `PARALLEL_PROOF_LIMIT`. If non-existent, will panic.
    pub fn new_from_env(
        da_service: Arc<Da>,
        vm: Vm,
        proof_mode: ProofGenMode,
    ) -> anyhow::Result<Self> {
        let thread_pool_size = std::env::var("PARALLEL_PROOF_LIMIT")
            .expect("PARALLEL_PROOF_LIMIT must be set")
            .parse::<usize>()
            .expect("PARALLEL_PROOF_LIMIT must be valid unsigned number");

        Self::new(da_service, vm, proof_mode, thread_pool_size)
    }

    /// Runs proving in a blocking manner. This just calls `start_proving` and waits for the result.
    pub async fn prove(&self, data: ProofData) -> Proof {
        let rx = self.start_proving(data).await;
        rx.await.expect("Proof channel should not close")
    }

    /// Starts the proving task in the background and returns a channel which will resolve
    /// once the proving is done. If there is not enough proving slots left, this function
    /// will block until it can get a slot and start the proof.
    pub async fn start_proving(&self, data: ProofData) -> oneshot::Receiver<Proof> {
        self.reserve_proof_slot().await;

        let ProofData {
            input,
            assumptions,
            elf,
        } = data;

        let mut vm = self.vm.clone();

        vm.add_hint(input);
        for assumption in assumptions {
            vm.add_assumption(assumption);
        }

        let ongoing_proof_count = self.ongoing_proof_count.clone();
        let proof_mode = self.proof_mode;
        let notifier = self.proof_done_notifier.clone();
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            info!("Starting proving task {}", id);

            let proof = make_proof(vm, elf, proof_mode).expect("Proof creation must not fail");

            *ongoing_proof_count.blocking_lock() -= 1;
            tx.send(proof).expect("Proof channel should not close");

            info!("Finished proving task {}", id);
            notifier.notify_one();
        });

        rx
    }

    async fn reserve_proof_slot(&self) {
        let mut ongoing_proof_count = self.ongoing_proof_count.lock().await;

        if *ongoing_proof_count < self.parallel_proof_limit {
            *ongoing_proof_count += 1;
            return;
        }
        // Release the lock manually just in case
        drop(ongoing_proof_count);

        warn!("Reached parallel proof limit, waiting for one of the proving tasks to finish");

        loop {
            self.proof_done_notifier.notified().await;

            let mut ongoing_proof_count = self.ongoing_proof_count.lock().await;
            if *ongoing_proof_count < self.parallel_proof_limit {
                *ongoing_proof_count += 1;
                return;
            }
        }
    }

    pub async fn submit_proof(
        &self,
        proof: Proof,
    ) -> anyhow::Result<<Da as DaService>::TransactionId> {
        let tx_request = DaTxRequest::ZKProof(proof);
        self.da_service
            .send_transaction(tx_request)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn submit_proofs(
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

    pub async fn recover_and_submit_proving_sessions(
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
