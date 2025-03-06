use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use borsh::BorshDeserialize;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::sync_l1;
use citrea_common::LightClientProverConfig;
use citrea_primitives::forks::fork_from_block_number;
use prover_services::{ParallelProverService, ProofData};
use sov_db::ledger_db::{LightClientProverLedgerOps, SharedLedgerOps};
use sov_db::schema::types::light_client_proof::StoredLightClientProofOutput;
use sov_db::schema::types::SlotNumber;
use sov_modules_api::{
    BatchProofCircuitOutputV2, BatchProofCircuitOutputV3, BlobReaderTrait, DaSpec, Zkvm,
};
use sov_prover_storage_manager::{ProverStorage, ProverStorageManager};
use sov_rollup_interface::da::{BlockHeaderTrait, DaDataLightClient, DaNamespace};
use sov_rollup_interface::mmr::Wtxid;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::batch_proof::output::v1::BatchProofCircuitOutputV1;
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use sov_rollup_interface::zk::{Proof, ZkvmHost};
use sov_rollup_interface::Network;
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

use crate::circuit::primitives::InitialValueProvider;
use crate::circuit::LightClientProofCircuit;
use crate::metrics::LIGHT_CLIENT_METRICS;

pub enum StartVariant {
    LastScanned(u64),
    FromBlock(u64),
}

pub struct L1BlockHandler<Vm, Da, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm + 'static,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone,
    Network: InitialValueProvider<Da::Spec>,
{
    network: Network,
    _prover_config: LightClientProverConfig,
    prover_service: Arc<ParallelProverService<Da, Vm>>,
    storage_manager: ProverStorageManager,
    ledger_db: DB,
    da_service: Arc<Da>,
    // TODO: maybe remove these
    _batch_prover_da_pub_key: Vec<u8>,
    _batch_proof_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
    light_client_proof_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
    light_client_proof_elfs: HashMap<SpecId, Vec<u8>>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    queued_l1_blocks: Arc<Mutex<VecDeque<<Da as DaService>::FilteredBlock>>>,
    backup_manager: Arc<BackupManager>,
    circuit: LightClientProofCircuit<ProverStorage, Da::Spec, Vm>,
}

impl<Vm, Da, DB> L1BlockHandler<Vm, Da, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone,
    Network: InitialValueProvider<Da::Spec>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: Network,
        prover_config: LightClientProverConfig,
        prover_service: Arc<ParallelProverService<Da, Vm>>,
        storage_manager: ProverStorageManager,
        ledger_db: DB,
        da_service: Arc<Da>,
        batch_prover_da_pub_key: Vec<u8>,
        batch_proof_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
        light_client_proof_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
        light_client_proof_elfs: HashMap<SpecId, Vec<u8>>,
        backup_manager: Arc<BackupManager>,
    ) -> Self {
        Self {
            network,
            _prover_config: prover_config,
            prover_service,
            storage_manager,
            ledger_db,
            da_service,
            _batch_prover_da_pub_key: batch_prover_da_pub_key,
            _batch_proof_code_commitments: batch_proof_code_commitments,
            light_client_proof_code_commitments,
            light_client_proof_elfs,
            l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            queued_l1_blocks: Arc::new(Mutex::new(VecDeque::new())),
            backup_manager,
            circuit: LightClientProofCircuit::new(),
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
        let l1_sync_worker = sync_l1(
            start_l1_height,
            self.da_service.clone(),
            self.queued_l1_blocks.clone(),
            self.l1_block_cache.clone(),
            LIGHT_CLIENT_METRICS.scan_l1_block.clone(),
        );
        tokio::pin!(l1_sync_worker);

        let backup_manager = self.backup_manager.clone();

        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.tick().await;
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                }
                _ = &mut l1_sync_worker => {},
                _ = interval.tick() => {
                    let _l1_guard = backup_manager.start_l1_processing().await;
                    if let Err(e) = self.process_queued_l1_blocks().await {
                        error!("Could not process queued L1 blocks and generate proof: {:?}", e);
                    }
                },
            }
        }
    }

    async fn process_queued_l1_blocks(&mut self) -> Result<(), anyhow::Error> {
        loop {
            let Some(l1_block) = self.queued_l1_blocks.lock().await.front().cloned() else {
                break;
            };
            self.process_l1_block(l1_block).await?;
            self.queued_l1_blocks.lock().await.pop_front();
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

        let (da_data, inclusion_proof, completeness_proof) = self
            .da_service
            .extract_relevant_blobs_with_proof(&l1_block, DaNamespace::ToLightClientProver);

        let mut assumptions = vec![];

        let previous_l1_height = l1_height - 1;
        let (light_client_proof_journal, l2_last_height, light_client_proof_output) = match self
            .ledger_db
            .get_light_client_proof_data_by_l1_height(previous_l1_height)?
        {
            Some(data) => {
                // LCPs are succinct receipts, we can make use of the assumption API
                let proof = data.proof;
                assumptions.push(proof);

                let db_output = data.light_client_proof_output;
                let output = LightClientCircuitOutput::from(db_output);

                // TODO: instead of serializing the output
                // we should just store and push the serialized proof as outputted from the circuit
                // that way modifications are less error prone
                (
                    Some(borsh::to_vec(&output)?),
                    output.last_l2_height,
                    Some(output),
                )
            }
            None => {
                // first time proving a light client proof
                tracing::warn!(
                    "Creating initial light client proof on L1 block #{}",
                    l1_height
                );
                (None, 0, None)
            }
        };

        let storage = self.storage_manager.create_storage_for_next_l2_height();

        // TODO: might need to iterate over da_data and call .full_data() on each
        let result = self.circuit.run_l1_block(
            storage,
            Default::default(),
            da_data.clone(),
            l1_block.header().clone(),
            light_client_proof_output,
            self.network.get_l2_genesis_root(),
            self.network.initial_batch_proof_method_ids(),
            &self.network.batch_prover_da_public_key(),
            &self.network.method_id_upgrade_authority_da_public_key(),
        );

        assert!(
            assumptions.len() == 0 || assumptions.len() == 1,
            "Assumptions should be either 0 or 1"
        );

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
            witness: result.witness,
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

        // Only save after the proof is generated
        self.storage_manager.finalize_storage(result.change_set);

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
    fn _verify_complete_proof(
        &self,
        proof: &Vec<u8>,
        light_client_l2_height: u64,
    ) -> anyhow::Result<bool> {
        let batch_proof_last_l2_height = match Vm::extract_output::<BatchProofCircuitOutputV3>(
            proof,
        ) {
            Ok(output) => output.last_l2_height,
            Err(e) => {
                warn!("Failed to extract post fork 2 output from proof: {:?}. Trying to extract pre fork 2 output", e);
                match Vm::extract_output::<BatchProofCircuitOutputV2>(proof) {
                    Ok(output) => output.last_l2_height,
                    Err(e) => {
                        warn!("Failed to extract post fork 1 output from proof: {:?}. Trying to extract pre fork 1 output", e);
                        if Vm::extract_output::<BatchProofCircuitOutputV1>(proof).is_err() {
                            return Err(anyhow::anyhow!(
                                "Failed to extract both pre-fork1 and fork1 output from proof"
                            ));
                        }
                        0
                    }
                }
            }
        };

        if batch_proof_last_l2_height <= light_client_l2_height && light_client_l2_height != 0 {
            return Err(anyhow::anyhow!(
                "Batch proof l2 height is less than latest light client proof l2 height"
            ));
        }

        let current_spec = fork_from_block_number(batch_proof_last_l2_height).spec_id;
        let batch_proof_method_id = self
            ._batch_proof_code_commitments
            .get(&current_spec)
            .expect("Batch proof code commitment not found");

        if let Err(e) = Vm::verify(proof.as_slice(), batch_proof_method_id) {
            warn!("Failed to verify batch proof: {:?}", e);
            Ok(false)
        } else {
            Ok(true)
        }
    }

    async fn _extract_batch_proofs(
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
                        if tx.sender().as_ref() == self._batch_prover_da_pub_key.as_slice() {
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
        let data = ProofData {
            input: borsh::to_vec(&circuit_input)?,
            assumptions,
            elf: light_client_elf,
        };

        let proof = prover_service.prove(data).await;
        Ok(proof)
    }
}
