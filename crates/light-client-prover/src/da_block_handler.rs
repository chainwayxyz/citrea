use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use borsh::BorshDeserialize;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::get_da_block_at_height;
use citrea_common::LightClientProverConfig;
use citrea_primitives::forks::fork_from_block_number;
use sov_db::ledger_db::{LightClientProverLedgerOps, SharedLedgerOps};
use sov_db::schema::types::{SlotNumber, StoredLightClientProofOutput};
use sov_modules_api::{BatchProofCircuitOutput, BlobReaderTrait, DaSpec, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, DaDataLightClient, DaNamespace};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::{
    LightClientCircuitInput, LightClientCircuitOutput, OldBatchProofCircuitOutput, Proof, ZkvmHost,
};
use sov_stf_runner::{ProofData, ProverService};
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::metrics::LIGHT_CLIENT_METRICS;

pub(crate) struct L1BlockHandler<Vm, Da, Ps, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone,
    Ps: ProverService,
{
    _prover_config: LightClientProverConfig,
    prover_service: Arc<Ps>,
    ledger_db: DB,
    da_service: Arc<Da>,
    batch_prover_da_pub_key: Vec<u8>,
    batch_proof_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
    light_client_proof_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
    light_client_proof_elfs: HashMap<SpecId, Vec<u8>>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    queued_l1_blocks: VecDeque<<Da as DaService>::FilteredBlock>,
}

impl<Vm, Da, Ps, DB> L1BlockHandler<Vm, Da, Ps, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<DaService = Da>,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prover_config: LightClientProverConfig,
        prover_service: Arc<Ps>,
        ledger_db: DB,
        da_service: Arc<Da>,
        batch_prover_da_pub_key: Vec<u8>,
        batch_proof_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
        light_client_proof_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
        light_client_proof_elfs: HashMap<SpecId, Vec<u8>>,
    ) -> Self {
        Self {
            _prover_config: prover_config,
            prover_service,
            ledger_db,
            da_service,
            batch_prover_da_pub_key,
            batch_proof_code_commitments,
            light_client_proof_code_commitments,
            light_client_proof_elfs,
            l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            queued_l1_blocks: VecDeque::new(),
        }
    }

    pub async fn run(mut self, start_l1_height: u64, cancellation_token: CancellationToken) {
        // if self.prover_config.enable_recovery {
        //     if let Err(e) = self.check_and_recover_ongoing_proving_sessions().await {
        //         error!("Failed to recover ongoing proving sessions: {:?}", e);
        //     }
        // } else {
        //     // If recovery is disabled, clear pending proving sessions
        //     self.ledger_db
        //         .clear_pending_proving_sessions()
        //         .expect("Failed to clear pending proving sessions");
        // }

        let (l1_tx, mut l1_rx) = mpsc::channel(1);
        let l1_sync_worker = sync_l1(
            start_l1_height,
            self.da_service.clone(),
            l1_tx,
            self.l1_block_cache.clone(),
        );
        tokio::pin!(l1_sync_worker);

        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.tick().await;
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                }
                _ = &mut l1_sync_worker => {},
                Some(l1_block) = l1_rx.recv() => {
                    self.queued_l1_blocks.push_back(l1_block);
                },
                _ = interval.tick() => {
                    if let Err(e) = self.process_queued_l1_blocks().await {
                        error!("Could not process queued L1 blocks and generate proof: {:?}", e);
                    }
                },
            }
        }
    }

    async fn process_queued_l1_blocks(&mut self) -> Result<(), anyhow::Error> {
        while !self.queued_l1_blocks.is_empty() {
            let l1_block = self
                .queued_l1_blocks
                .front()
                .expect("Pending l1 blocks cannot be empty");

            self.process_l1_block(l1_block).await?;

            self.queued_l1_blocks.pop_front();
        }

        Ok(())
    }

    async fn process_l1_block(&self, l1_block: &Da::FilteredBlock) -> anyhow::Result<()> {
        let l1_hash = l1_block.header().hash().into();
        let l1_height = l1_block.header().height();

        // Set the l1 height of the l1 hash
        self.ledger_db
            .set_l1_height_of_l1_hash(l1_hash, l1_height)
            .expect("Setting l1 height of l1 hash in ledger db");

        let (mut da_data, inclusion_proof, completeness_proof) = self
            .da_service
            .extract_relevant_blobs_with_proof(l1_block, DaNamespace::ToLightClientProver);

        // Even though following extract_batch_proofs call does full_data on batch proofs,
        // we also need to do it for BatchProofMethodId txs
        da_data.iter_mut().for_each(|tx| {
            tx.full_data();
        });

        let mut assumptions = vec![];

        let previous_l1_height = l1_height - 1;
        let (light_client_proof_journal, l2_last_height) = match self
            .ledger_db
            .get_light_client_proof_data_by_l1_height(previous_l1_height)?
        {
            Some(data) => {
                let proof = data.proof;
                assumptions.push(proof);

                let db_output = data.light_client_proof_output;
                let output = LightClientCircuitOutput::from(db_output);
                // TODO: instead of serializing the output
                // we should just store and push the serialized proof as outputted from the circuit
                // that way modifications are less error prone
                (Some(borsh::to_vec(&output)?), output.last_l2_height)
            }
            None => {
                // first time proving a light client proof
                tracing::warn!(
                    "Creating initial light client proof on L1 block #{}",
                    l1_height
                );
                (None, 0)
            }
        };

        let batch_proofs = self.extract_batch_proofs(&mut da_data, l1_hash).await;
        tracing::info!(
            "Block {} has {} batch proofs",
            l1_height,
            batch_proofs.len()
        );

        // index only incremented for complete and aggregated proofs, in line with the circuit
        let mut proof_index = 0u32;
        let mut expected_to_fail_hint = vec![];

        for batch_proof in batch_proofs {
            // TODO handle aggreagates
            if let DaDataLightClient::Complete(proof) = batch_proof {
                let batch_proof_last_l2_height = match Vm::extract_output::<
                    BatchProofCircuitOutput<<Da as DaService>::Spec, [u8; 32]>,
                >(&proof)
                {
                    Ok(output) => output.last_l2_height,
                    Err(e) => {
                        info!("Failed to extract post fork 1 output from proof: {:?}. Trying to extract pre fork 1 output", e);
                        if Vm::extract_output::<
                            OldBatchProofCircuitOutput<<Da as DaService>::Spec, [u8; 32]>,
                        >(&proof)
                        .is_err()
                        {
                            tracing::info!(
                                "Failed to extract pre fork1 and fork1 output from proof"
                            );
                            continue;
                        }
                        // If this is a pre fork 1 proof, then we need to convert it to post fork 1 proof
                        0
                    }
                };

                if batch_proof_last_l2_height <= l2_last_height && l2_last_height != 0 {
                    proof_index += 1;
                    continue;
                }

                let current_spec = fork_from_block_number(batch_proof_last_l2_height).spec_id;
                let batch_proof_method_id = self
                    .batch_proof_code_commitments
                    .get(&current_spec)
                    .expect("Batch proof code commitment not found");
                if let Err(e) = Vm::verify(proof.as_slice(), batch_proof_method_id) {
                    tracing::error!("Failed to verify batch proof: {:?}", e);
                    expected_to_fail_hint.push(proof_index);
                } else {
                    assumptions.push(proof);
                }

                proof_index += 1;
            }
        }

        tracing::debug!("assumptions len: {:?}", assumptions.len());

        let current_fork = fork_from_block_number(l2_last_height);
        let light_client_proof_code_commitment = self
            .light_client_proof_code_commitments
            .get(&current_fork.spec_id)
            .expect("Fork should have a guest code attached");
        let light_client_elf = self
            .light_client_proof_elfs
            .get(&current_fork.spec_id)
            .expect("Fork should have a guest code attached")
            .clone();

        let circuit_input = LightClientCircuitInput {
            da_data,
            inclusion_proof,
            completeness_proof,
            da_block_header: l1_block.header().clone(),
            light_client_proof_method_id: light_client_proof_code_commitment.clone().into(),
            previous_light_client_proof_journal: light_client_proof_journal,
            expected_to_fail_hint,
        };

        let proof = self
            .prove(light_client_elf, circuit_input, assumptions)
            .await?;

        let circuit_output = Vm::extract_output::<LightClientCircuitOutput>(&proof)
            .expect("Should deserialize valid proof");

        tracing::info!(
            "Generated proof for L1 block: {l1_height} output={:?}",
            circuit_output
        );

        let stored_proof_output = StoredLightClientProofOutput::from(circuit_output);

        self.ledger_db.insert_light_client_proof_data_by_l1_height(
            l1_height,
            proof,
            stored_proof_output,
        )?;

        self.ledger_db
            .set_last_scanned_l1_height(SlotNumber(l1_block.header().height()))
            .expect("Saving last scanned l1 height to ledger db");

        LIGHT_CLIENT_METRICS.current_l1_block.set(l1_height as f64);

        Ok(())
    }

    async fn extract_batch_proofs(
        &self,
        da_data: &mut [<<Da as DaService>::Spec as DaSpec>::BlobTransaction],
        da_slot_hash: [u8; 32], // passing this as an argument is not clever
    ) -> Vec<DaDataLightClient> {
        let mut batch_proofs = Vec::new();

        da_data.iter_mut().for_each(|tx| {
            // Check for commitment
            if tx.sender().as_ref() == self.batch_prover_da_pub_key.as_slice() {
                let data = DaDataLightClient::try_from_slice(tx.full_data());

                if let Ok(proof) = data {
                    batch_proofs.push(proof);
                } else {
                    tracing::warn!(
                        "Found broken DA data in block 0x{}: {:?}",
                        hex::encode(da_slot_hash),
                        data
                    );
                }
            }
        });
        batch_proofs
    }

    async fn prove(
        &self,
        light_client_elf: Vec<u8>,
        circuit_input: LightClientCircuitInput<<Da as DaService>::Spec>,
        assumptions: Vec<Vec<u8>>,
    ) -> Result<Proof, anyhow::Error> {
        let prover_service = self.prover_service.as_ref();

        prover_service
            .add_proof_data(ProofData {
                input: borsh::to_vec(&circuit_input)?,
                assumptions,
                elf: light_client_elf,
            })
            .await;

        let proofs = self.prover_service.prove().await?;

        assert_eq!(proofs.len(), 1);

        Ok(proofs[0].clone())
    }
}

async fn sync_l1<Da>(
    start_l1_height: u64,
    da_service: Arc<Da>,
    sender: mpsc::Sender<Da::FilteredBlock>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
) where
    Da: DaService,
{
    let mut l1_height = start_l1_height;
    info!("Starting to sync from L1 height {}", l1_height);

    'block_sync: loop {
        let last_finalized_l1_block_header =
            match da_service.get_last_finalized_block_header().await {
                Ok(header) => header,
                Err(e) => {
                    error!("Could not fetch last finalized L1 block header: {}", e);
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

        let new_l1_height = last_finalized_l1_block_header.height();

        for block_number in l1_height + 1..=new_l1_height {
            let l1_block =
                match get_da_block_at_height(&da_service, block_number, l1_block_cache.clone())
                    .await
                {
                    Ok(block) => block,
                    Err(e) => {
                        error!("Could not fetch last finalized L1 block: {}", e);
                        sleep(Duration::from_secs(2)).await;
                        continue 'block_sync;
                    }
                };
            if block_number > l1_height {
                l1_height = block_number;
                if let Err(e) = sender.send(l1_block).await {
                    error!("Could not notify about L1 block: {}", e);
                    continue 'block_sync;
                }
            }
        }

        sleep(Duration::from_secs(2)).await;
    }
}
