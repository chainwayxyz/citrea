use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::Arc;

use anyhow::anyhow;
use borsh::{BorshDeserialize, BorshSerialize};
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::{Proof, StateTransitionData, ZkvmHost};
use sov_stf_runner::{ProofProcessingStatus, ProverServiceError, WitnessSubmissionStatus};

use crate::prover_service::ProofGenConfig;

pub(crate) enum ProverStatus {
    WitnessSubmitted(Vec<u8>),
    ProvingInProgress,
    #[allow(dead_code)]
    Proved(Proof),
    Err(anyhow::Error),
}

struct ProverState<Da: DaSpec> {
    prover_status: HashMap<Da::SlotHash, ProverStatus>,
    pending_tasks_count: usize,
}

impl<Da: DaSpec> ProverState<Da> {
    fn remove(&mut self, hash: &Da::SlotHash) -> Option<ProverStatus> {
        self.prover_status.remove(hash)
    }

    fn set_to_proving(&mut self, hash: Da::SlotHash) -> Option<ProverStatus> {
        self.prover_status
            .insert(hash, ProverStatus::ProvingInProgress)
    }

    fn set_to_proved(
        &mut self,
        hash: Da::SlotHash,
        proof: Result<Proof, anyhow::Error>,
    ) -> Option<ProverStatus> {
        match proof {
            Ok(p) => self.prover_status.insert(hash, ProverStatus::Proved(p)),
            Err(e) => self.prover_status.insert(hash, ProverStatus::Err(e)),
        }
    }

    fn get_prover_status(&self, hash: Da::SlotHash) -> Option<&ProverStatus> {
        self.prover_status.get(&hash)
    }

    fn inc_task_count_if_not_busy(&mut self, num_threads: usize) -> bool {
        if self.pending_tasks_count >= num_threads {
            return false;
        }

        self.pending_tasks_count += 1;
        true
    }

    fn dec_task_count(&mut self) {
        assert!(self.pending_tasks_count > 0);
        self.pending_tasks_count -= 1;
    }
}

// A prover that generates proofs in parallel using a thread pool. If the pool is saturated,
// the prover will reject new jobs.
pub(crate) struct Prover<Da: DaService> {
    prover_state: Arc<Mutex<ProverState<Da::Spec>>>,
    num_threads: usize,
    pool: rayon::ThreadPool,
}

impl<Da> Prover<Da>
where
    Da: DaService,
{
    pub(crate) fn new(num_threads: usize) -> anyhow::Result<Self> {
        Ok(Self {
            num_threads,
            pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build()
                .map_err(|e| anyhow!(e))?,

            prover_state: Arc::new(Mutex::new(ProverState {
                prover_status: Default::default(),
                pending_tasks_count: Default::default(),
            })),
        })
    }

    pub(crate) fn submit_witness(
        &self,
        input: Vec<u8>,
        da_slot_hash: <Da::Spec as DaSpec>::SlotHash,
    ) -> WitnessSubmissionStatus {
        let header_hash = da_slot_hash;
        let data = ProverStatus::WitnessSubmitted(input);

        let mut prover_state = self.prover_state.lock();
        let entry = prover_state.prover_status.entry(header_hash);

        match entry {
            Entry::Occupied(_) => WitnessSubmissionStatus::WitnessExist,
            Entry::Vacant(v) => {
                v.insert(data);
                WitnessSubmissionStatus::SubmittedForProving
            }
        }
    }

    pub(crate) fn start_proving<Vm, V>(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
        config: Arc<Mutex<ProofGenConfig<V, Da, Vm>>>,
        mut vm: Vm,
        zk_storage: V::PreState,
    ) -> Result<ProofProcessingStatus, ProverServiceError>
    where
        Vm: ZkvmHost + 'static,
        V: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync + 'static,
        V::PreState: Send + Sync + 'static,
    {
        let prover_state_clone = self.prover_state.clone();
        let mut prover_state = self.prover_state.lock();

        let prover_status = prover_state
            .remove(&block_header_hash)
            .ok_or_else(|| anyhow::anyhow!("Missing witness for block: {:?}", block_header_hash))?;

        match prover_status {
            ProverStatus::WitnessSubmitted(state_transition_data) => {
                let start_prover = prover_state.inc_task_count_if_not_busy(self.num_threads);
                // Initiate a new proving job only if the prover is not busy.
                if start_prover {
                    prover_state.set_to_proving(block_header_hash.clone());
                    vm.add_hint(state_transition_data);

                    self.pool.spawn(move || {
                        tracing::debug_span!("guest_execution").in_scope(|| {
                            let proof = make_proof(vm, config, zk_storage);

                            let mut prover_state = prover_state_clone.lock();

                            prover_state.set_to_proved(block_header_hash, proof);
                            prover_state.dec_task_count();
                        })
                    });

                    Ok(ProofProcessingStatus::ProvingInProgress)
                } else {
                    Ok(ProofProcessingStatus::Busy)
                }
            }
            ProverStatus::ProvingInProgress => Err(anyhow::anyhow!(
                "Proof generation for {:?} still in progress",
                block_header_hash
            )
            .into()),
            ProverStatus::Proved(_) => Err(anyhow::anyhow!(
                "Witness for block_header_hash {:?}, submitted multiple times.",
                block_header_hash,
            )
            .into()),
            ProverStatus::Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn get_prover_status_for_da_submission(
        &self,
        block_header_hash: <Da::Spec as DaSpec>::SlotHash,
    ) -> Result<ProverStatus, anyhow::Error> {
        let mut prover_state = self.prover_state.lock();

        let status = prover_state.get_prover_status(block_header_hash.clone());

        match status {
            Some(ProverStatus::ProvingInProgress) => Ok(ProverStatus::ProvingInProgress),
            Some(ProverStatus::Proved(_)) => {
                // we know its proved so we can unwrap
                let status = prover_state.remove(&block_header_hash).unwrap();

                Ok(status)
            }
            Some(ProverStatus::WitnessSubmitted(_)) => Err(anyhow::anyhow!(
                "Witness for {:?} was submitted, but the proof generation is not triggered.",
                block_header_hash
            )),
            Some(ProverStatus::Err(e)) => Err(anyhow::anyhow!(e.to_string())),
            None => Err(anyhow::anyhow!(
                "Missing witness for: {:?}",
                block_header_hash
            )),
        }
    }
}

fn make_proof<V, Vm, Da>(
    mut vm: Vm,
    config: Arc<Mutex<ProofGenConfig<V, Da, Vm>>>,
    zk_storage: V::PreState,
) -> Result<Proof, anyhow::Error>
where
    Da: DaService,
    Vm: ZkvmHost + 'static,
    V: StateTransitionFunction<Vm::Guest, Da::Spec> + Send + Sync + 'static,
    V::PreState: Send + Sync + 'static,
{
    let mut config = config.lock();
    match config.deref_mut() {
        ProofGenConfig::Skip => Ok(Proof::PublicInput(Vec::default())),
        ProofGenConfig::Simulate(ref mut verifier) => verifier
            .run_sequencer_commitments_in_da_slot(vm.simulate_with_hints(), zk_storage)
            .map(|_| Proof::PublicInput(Vec::default()))
            .map_err(|e| anyhow::anyhow!("Guest execution must succeed but failed with {:?}", e)),
        ProofGenConfig::Execute => vm.run(false),
        ProofGenConfig::Prover => vm.run(true),
    }
}
