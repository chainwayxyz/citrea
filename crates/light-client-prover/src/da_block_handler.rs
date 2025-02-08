use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use borsh::BorshDeserialize;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::sync_l1;
use citrea_common::LightClientProverConfig;
use citrea_primitives::forks::fork_from_block_number;
use sov_db::ledger_db::{LightClientProverLedgerOps, SharedLedgerOps};
use sov_db::mmr_db::MmrDB;
use sov_db::schema::types::{SlotNumber, StoredLightClientProofOutput};
use sov_modules_api::{BatchProofCircuitOutputV2, BlobReaderTrait, DaSpec, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, DaDataLightClient, DaNamespace};
use sov_rollup_interface::mmr::{MMRChunk, MMRNative, Wtxid};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::batch_proof::output::v1::BatchProofCircuitOutputV1;
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use sov_stf_runner::{ProofData, ProverService};
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::metrics::LIGHT_CLIENT_METRICS;

pub enum StartVariant {
    LastScanned(u64),
    FromBlock(u64),
}

pub struct L1BlockHandler<Vm, Da, Ps, DB>
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
    mmr_native: MMRNative<MmrDB>,
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
        mmr_db: MmrDB,
    ) -> Self {
        let mmr_native = MMRNative::new(mmr_db);
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
            mmr_native,
        }
    }

    pub async fn run(
        mut self,
        last_l1_height_scanned: StartVariant,
        cancellation_token: CancellationToken,
    ) {
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
        let start_l1_height = match last_l1_height_scanned {
            StartVariant::LastScanned(height) => height + 1, // last scanned block + 1
            StartVariant::FromBlock(height) => height,       // first block to scan
        };
        let (l1_tx, mut l1_rx) = mpsc::channel(1);
        let l1_sync_worker = sync_l1(
            start_l1_height,
            self.da_service.clone(),
            l1_tx,
            self.l1_block_cache.clone(),
            LIGHT_CLIENT_METRICS.scan_l1_block.clone(),
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
                .expect("Pending l1 blocks cannot be empty")
                .clone();

            self.process_l1_block(l1_block).await?;

            self.queued_l1_blocks.pop_front();
        }

        Ok(())
    }

    async fn process_l1_block(&mut self, l1_block: Da::FilteredBlock) -> anyhow::Result<()> {
        let l1_hash = l1_block.header().hash().into();
        let l1_height = l1_block.header().height();

        // Set the l1 height of the l1 hash
        self.ledger_db
            .set_l1_height_of_l1_hash(l1_hash, l1_height)
            .expect("Setting l1 height of l1 hash in ledger db");

        let (mut da_data, inclusion_proof, completeness_proof) = self
            .da_service
            .extract_relevant_blobs_with_proof(&l1_block, DaNamespace::ToLightClientProver);

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

        let mut unused_chunks = BTreeMap::<Wtxid, Vec<u8>>::new();
        let mut mmr_hints = vec![];
        // index only incremented for complete and aggregated proofs, in line with the circuit
        let mut proof_index = 0u32;
        let mut expected_to_fail_hint = vec![];

        'proof_loop: for (wtxid, batch_proof) in batch_proofs {
            info!("Batch proof wtxid={}", hex::encode(wtxid));
            match batch_proof {
                DaDataLightClient::Complete(proof) => {
                    info!("It is complete proof");
                    match self.verify_complete_proof(&proof, l2_last_height) {
                        Ok(true) => {
                            info!("Complete proof verified successfully");
                            assumptions.push(proof);
                            proof_index += 1;
                        }
                        Ok(false) => {
                            warn!("Complete proof is expected to fail");
                            expected_to_fail_hint.push(proof_index);
                            proof_index += 1;
                        }
                        Err(err) => {
                            error!("Batch proof verification failed: {err}");
                        }
                    }
                }
                DaDataLightClient::Aggregate(_txids, wtxids) => {
                    info!("It is aggregate proof with {} chunks", wtxids.len());
                    // Ensure that aggregate has all the needed chunks
                    let mut used_chunk_count = 0;
                    for wid in &wtxids {
                        if unused_chunks.contains_key(wid) {
                            used_chunk_count += 1;
                            continue;
                        }
                        if !self.mmr_native.contains(*wid)? {
                            warn!("Aggregate is unprovable due to missing chunks");
                            continue 'proof_loop;
                        }
                    }

                    info!(
                        "Aggregate has all needed chunks, {} from current block, {} from previous blocks",
                        used_chunk_count,
                        wtxids.len() - used_chunk_count,
                    );

                    // Recollect the complete proof from chunks
                    let mut complete_proof = vec![];
                    // Used for re-adding chunks back in case of failure
                    let mut used_chunk_ptrs = Vec::with_capacity(used_chunk_count);
                    for wtxid in wtxids {
                        if let Some(chunk) = unused_chunks.remove(&wtxid) {
                            used_chunk_ptrs.push((complete_proof.len(), chunk.len(), wtxid));
                            complete_proof.extend(chunk);
                        } else {
                            let (chunk, proof) = self
                                .mmr_native
                                .generate_proof(wtxid)?
                                .expect("Chunk wtxid must exist");
                            complete_proof.extend_from_slice(&chunk.body);
                            mmr_hints.push((chunk, proof));
                        }
                    }

                    info!("Aggregate proof reassembled from chunks");

                    let reinsert_used_chunks = || {
                        for (idx, size, wtxid) in used_chunk_ptrs {
                            let chunk = complete_proof[idx..idx + size].to_vec();
                            unused_chunks.insert(wtxid, chunk);
                        }
                    };

                    let Ok(complete_proof) = self.da_service.decompress_chunks(&complete_proof)
                    else {
                        error!(
                            "Failed to decompress complete chunks of aggregate {}",
                            hex::encode(wtxid)
                        );
                        reinsert_used_chunks();
                        continue;
                    };

                    match self.verify_complete_proof(&complete_proof, l2_last_height) {
                        Ok(true) => {
                            info!("Aggregate proof verified successfully");
                            assumptions.push(complete_proof);
                            proof_index += 1;
                        }
                        Ok(false) => {
                            warn!("Aggregate proof is expected to fail");
                            expected_to_fail_hint.push(proof_index);
                            proof_index += 1;
                        }
                        Err(err) => {
                            error!("Invalid aggregate batch proof found: {err}");
                            reinsert_used_chunks();
                        }
                    }
                }
                DaDataLightClient::Chunk(body) => {
                    info!("It is chunk proof");
                    // For now, this chunk is unused by any aggregate in the block.
                    unused_chunks.insert(wtxid, body);
                }
                _ => {
                    continue;
                }
            }
        }

        tracing::debug!("assumptions len: {:?}", assumptions.len());

        // Add unused chunks to MMR native.
        // Up until this point, the proof has been generated by aggregates in the block,
        // so it's okay to update the MMR tree now.
        if !unused_chunks.is_empty() {
            info!("Adding {} more chunks to mmr", unused_chunks.len());
            for (wtxid, body) in unused_chunks.into_iter() {
                self.mmr_native.append(MMRChunk::new(wtxid, body))?;
            }
        }

        // This is not exactly right, but works for now because we have a single elf for
        // light client proof circuit.
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
            mmr_hints: mmr_hints.into(),
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

    /// Verifies complete proof. Returns:
    ///
    /// - Ok(true) -> proof is successfully parsed, not a duplicate, and verified
    /// - Ok(false) -> proof is successfully parsed, not a duplicate, but verification failed
    /// - Err(_) -> proof is either unparseable or a duplicate
    fn verify_complete_proof(
        &self,
        proof: &Vec<u8>,
        light_client_l2_height: u64,
    ) -> anyhow::Result<bool> {
        let batch_proof_last_l2_height = match Vm::extract_output::<
            BatchProofCircuitOutputV2<<Da as DaService>::Spec>,
        >(proof)
        {
            Ok(output) => output.last_l2_height,
            Err(e) => {
                warn!("Failed to extract post fork 1 output from proof: {:?}. Trying to extract pre fork 1 output", e);
                if Vm::extract_output::<BatchProofCircuitOutputV1<Da::Spec>>(proof).is_err() {
                    return Err(anyhow::anyhow!(
                        "Failed to extract both pre-fork1 and fork1 output from proof"
                    ));
                }
                0
            }
        };

        if batch_proof_last_l2_height <= light_client_l2_height && light_client_l2_height != 0 {
            return Err(anyhow::anyhow!(
                "Batch proof l2 height is less than latest light client proof l2 height"
            ));
        }

        let current_spec = fork_from_block_number(batch_proof_last_l2_height).spec_id;
        let batch_proof_method_id = self
            .batch_proof_code_commitments
            .get(&current_spec)
            .expect("Batch proof code commitment not found");

        if let Err(e) = Vm::verify(proof.as_slice(), batch_proof_method_id) {
            warn!("Failed to verify batch proof: {:?}", e);
            Ok(false)
        } else {
            Ok(true)
        }
    }

    async fn extract_batch_proofs(
        &self,
        da_data: &mut [<<Da as DaService>::Spec as DaSpec>::BlobTransaction],
        da_slot_hash: [u8; 32], // passing this as an argument is not clever
    ) -> Vec<(Wtxid, DaDataLightClient)> {
        let mut batch_proofs = Vec::new();

        da_data.iter_mut().for_each(|tx| {
            if let Ok(data) = DaDataLightClient::try_from_slice(tx.full_data()) {
                match data {
                    DaDataLightClient::Chunk(_) => {
                        batch_proofs.push((tx.wtxid().expect("Blob should have wtxid"), data))
                    }
                    _ => {
                        if tx.sender().as_ref() == self.batch_prover_da_pub_key.as_slice() {
                            batch_proofs.push((tx.wtxid().expect("Blob should have wtxid"), data));
                        }
                    }
                }
            } else {
                tracing::warn!(
                    "Found broken DA data in block 0x{}",
                    hex::encode(da_slot_hash)
                );
            }
            // Check for commitment
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
                is_post_genesis_batch: false,
            })
            .await;

        let proofs = self.prover_service.prove().await?;

        assert_eq!(proofs.len(), 1);

        Ok(proofs[0].clone())
    }
}
