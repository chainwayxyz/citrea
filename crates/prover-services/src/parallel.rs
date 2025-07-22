use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use rand::Rng;
use sov_rollup_interface::da::DaTxRequest;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::{Proof, ProofWithJob, ReceiptType, ZkvmHost};
use tokio::sync::{oneshot, Mutex, Notify};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::metrics::PARALLEL_PROVER_METRICS;
use crate::{ProofData, ProofGenMode, ProofWithDuration};

/// Prover service capable of invoking the zkVM proving sessions in parallel.
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
}

impl<Da, Vm> ParallelProverService<Da, Vm>
where
    Da: DaService,
    Vm: ZkvmHost,
{
    /// Creates a new `ParallelProverService`. Panics if parallel proof limit is 0.
    pub fn new(
        da_service: Arc<Da>,
        vm: Vm,
        proof_mode: ProofGenMode,
        parallel_proof_limit: usize,
    ) -> anyhow::Result<Self> {
        assert!(
            parallel_proof_limit > 0,
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
            parallel_proof_limit,
            ongoing_proof_count: Default::default(),
            proof_done_notifier: Default::default(),
            proof_mode,
            da_service,
            vm,
        })
    }

    /// Creates a new `ParallelProverService` with thread_pool_size retrieved from
    /// environment variable `PARALLEL_PROOF_LIMIT`. If non-existent, will panic.
    pub fn new_from_env(
        da_service: Arc<Da>,
        vm: Vm,
        proof_mode: ProofGenMode,
    ) -> anyhow::Result<Self> {
        let parallel_proof_limit = std::env::var("PARALLEL_PROOF_LIMIT")
            .expect("PARALLEL_PROOF_LIMIT must be set")
            .parse::<usize>()
            .expect("PARALLEL_PROOF_LIMIT must be valid unsigned number");

        Self::new(da_service, vm, proof_mode, parallel_proof_limit)
    }

    /// Runs proving in a blocking manner. This just calls `start_proving` and waits for the result.
    ///
    /// * `data` - the proof data to be used for generating a proof
    /// * `receipt_type` - the expected receipt type of the proof
    pub async fn prove(
        &self,
        data: ProofData,
        receipt_type: ReceiptType,
    ) -> anyhow::Result<ProofWithDuration> {
        let job_id = Uuid::nil();
        let rx = self.start_proving(data, receipt_type, job_id).await?;
        Ok(rx.await.expect("Proof channel should not close"))
    }

    /// Starts the proving task in the background and returns a channel which will resolve
    /// once the proving is done. If there is not enough proving slots left, this function
    /// will block until it can get a slot and start the proof.
    ///
    /// ## Arguments
    ///
    /// * `data` - the proof data to be used for generating a proof
    /// * `receipt_type` - the expected receipt type of the proof
    /// * `job_id` - the job id that is correlated to the proof
    ///
    /// ## Returns
    ///
    /// * a channel that will resolve once the proving job is done
    #[instrument(name = "ParallelProverService", skip_all)]
    pub async fn start_proving(
        &self,
        data: ProofData,
        receipt_type: ReceiptType,
        job_id: Uuid,
    ) -> anyhow::Result<oneshot::Receiver<ProofWithDuration>> {
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

        // start proof immediately in the background
        let proof_start_time = std::time::Instant::now();
        let proof_rx = make_proof(vm, job_id, elf, self.proof_mode, receipt_type)
            .context("Failed to start proving")?;
        debug!("Started proving job");

        let ongoing_proof_count = self.ongoing_proof_count.clone();
        let notifier = self.proof_done_notifier.clone();
        let (tx, rx) = oneshot::channel();
        // the reason we pipe the proof_rx to a new channel is because we need to
        // keep track of the number of ongoing proofs and notify the caller when the proof is done
        tokio::spawn(async move {
            let proof = proof_rx.await;

            *ongoing_proof_count.lock().await -= 1;
            PARALLEL_PROVER_METRICS.ongoing_proving_jobs.decrement(1);

            match proof {
                Ok(proof) => {
                    let duration = Instant::now()
                        .saturating_duration_since(proof_start_time)
                        .as_secs_f64();
                    let proof_with_duration = ProofWithDuration {
                        proof: proof.proof,
                        duration,
                    };
                    tx.send(proof_with_duration)
                        .expect("Proof channel should not close");
                }
                Err(e) => {
                    // even if we can't send the proof to the caller, we still send notification for
                    // rest of the awaiters to continue, hence, no return
                    error!("Vm proving channel closed abruptly: {}", e);
                }
            }

            debug!("Finished proving job");
            notifier.notify_one();
        });

        Ok(rx)
    }

    /// Reserves a proof slot. If the limit is reached, it will wait for a proof to finish.
    async fn reserve_proof_slot(&self) {
        let mut ongoing_proof_count = self.ongoing_proof_count.lock().await;
        // try to reserve a slot if there is one available
        if *ongoing_proof_count < self.parallel_proof_limit {
            *ongoing_proof_count += 1;
            PARALLEL_PROVER_METRICS
                .ongoing_proving_jobs
                .set(*ongoing_proof_count as f64);
            return;
        }
        // release the lock manually just in case
        drop(ongoing_proof_count);

        PARALLEL_PROVER_METRICS
            .proof_count_waiting_in_queue
            .increment(1);
        warn!("Reached parallel proof limit, waiting for one of the proving tasks to finish");

        loop {
            // wait for a proof job to send a finish notification
            self.proof_done_notifier.notified().await;

            // try to reserve a slot again, it is possible that there were multiple awaiters,
            // hence, whoever gets the lock first will be able to reserve a slot
            let mut ongoing_proof_count = self.ongoing_proof_count.lock().await;
            if *ongoing_proof_count < self.parallel_proof_limit {
                *ongoing_proof_count += 1;
                PARALLEL_PROVER_METRICS
                    .ongoing_proving_jobs
                    .set(*ongoing_proof_count as f64);
                PARALLEL_PROVER_METRICS
                    .proof_count_waiting_in_queue
                    .decrement(1);
                return;
            }
        }
    }

    /// Submits the zk proof to the DA service, returning transaction id.
    #[instrument(name = "ParallelProverService", skip_all, fields(job_id = _job_id.to_string()))]
    pub async fn submit_proof(
        &self,
        proof: Proof,
        _job_id: Uuid,
    ) -> anyhow::Result<<Da as DaService>::TransactionId> {
        let tx_request = DaTxRequest::ZKProof(proof);
        info!("Submitting proof to DA service");
        self.da_service
            .send_transaction(tx_request)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    // Only used in tests
    pub async fn submit_proofs(
        &self,
        proofs: Vec<Proof>,
    ) -> anyhow::Result<Vec<(<Da as DaService>::TransactionId, Proof)>> {
        let mut tx_and_proof = Vec::with_capacity(proofs.len());
        let job_id = Uuid::nil();
        for proof in proofs {
            let tx_id = self.submit_proof(proof.clone(), job_id).await?;
            tx_and_proof.push((tx_id, proof));
        }
        Ok(tx_and_proof)
    }

    /// Starts a session recovery.
    pub fn start_session_recovery(&self) -> anyhow::Result<Vec<oneshot::Receiver<ProofWithJob>>> {
        let vm = self.vm.clone();
        vm.start_session_recovery()
    }
}

/// Runs the zkVM proving session. Decides on whether to produce a real proof or a fake proof based on the proof mode.
fn make_proof<Vm>(
    mut vm: Vm,
    job_id: Uuid,
    elf: Vec<u8>,
    proof_mode: ProofGenMode,
    receipt_type: ReceiptType,
) -> Result<oneshot::Receiver<ProofWithJob>, anyhow::Error>
where
    Vm: ZkvmHost,
{
    let with_prove = match proof_mode {
        ProofGenMode::Skip => {
            unimplemented!("ProofGenMode::Skip is not yet implemented")
        }
        ProofGenMode::Execute => false,
        ProofGenMode::ProveWithSampling => {
            // `make_proof` is called with a probability in this case.
            // When it's called, we have to produce a real proof.
            true
        }
        ProofGenMode::ProveWithSamplingWithFakeProofs(proof_sampling) => {
            // `make_proof` is called unconditionally in this case.
            // When it's called, we have to calculate the probabiliry for a proof
            //  and produce a real proof if we are lucky. If unlucky - produce a fake proof.
            proof_sampling == 0 || rand::thread_rng().gen_range(0..proof_sampling) == 0
        }
    };

    let rx = vm.run(job_id, elf, receipt_type, with_prove)?;
    Ok(rx)
}
