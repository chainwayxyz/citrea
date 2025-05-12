use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::sync_l1;
use citrea_common::LightClientProverConfig;
use citrea_primitives::forks::fork_from_block_number;
use prover_services::{ParallelProverService, ProofData};
use reth_tasks::shutdown::GracefulShutdown;
use sov_db::ledger_db::{LightClientProverLedgerOps, SharedLedgerOps};
use sov_db::schema::types::light_client_proof::StoredLightClientProofOutput;
use sov_db::schema::types::SlotNumber;
use sov_modules_api::Zkvm;
use sov_prover_storage_manager::{ProverStorage, ProverStorageManager};
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use sov_rollup_interface::zk::{Proof, ReceiptType, ZkvmHost};
use sov_rollup_interface::Network;
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tracing::{error, instrument};

use crate::circuit::initial_values::InitialValueProvider;
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
            light_client_proof_code_commitments,
            light_client_proof_elfs,
            l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            queued_l1_blocks: Arc::new(Mutex::new(VecDeque::new())),
            backup_manager,
            circuit: LightClientProofCircuit::new(),
        }
    }

    #[instrument(name = "L1BlockHandler", skip_all)]
    pub async fn run(
        mut self,
        last_l1_height_scanned: StartVariant,
        mut shutdown_signal: GracefulShutdown,
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
                _ = &mut shutdown_signal => {
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

        let (da_data, inclusion_proof, completeness_proof) =
            self.da_service.extract_relevant_blobs_with_proof(&l1_block);

        let previous_l1_height = l1_height - 1;
        let (previous_lcp_proof, l2_last_height, previous_lcp_output) = match self
            .ledger_db
            .get_light_client_proof_data_by_l1_height(previous_l1_height)?
        {
            Some(data) => {
                let output = LightClientCircuitOutput::from(data.light_client_proof_output);
                (Some(data.proof), output.last_l2_height, Some(output))
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
            da_data,
            l1_block.header().clone(),
            previous_lcp_output,
            self.network.get_l2_genesis_root(),
            self.network.initial_batch_proof_method_ids(),
            &self.network.batch_prover_da_public_key(),
            &self.network.sequencer_da_public_key(),
            &self.network.method_id_upgrade_authority_da_public_key(),
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
            inclusion_proof,
            completeness_proof,
            da_block_header: l1_block.header().clone(),
            light_client_proof_method_id: light_client_proof_code_commitment.clone().into(),
            previous_light_client_proof: previous_lcp_proof,
            witness: result.witness,
        };

        let proof = self.prove(light_client_elf, circuit_input, vec![]).await?;

        let circuit_output = Vm::extract_output::<LightClientCircuitOutput>(&proof)
            .expect("Should deserialize valid proof");

        tracing::info!(
            "Generated proof for L1 block: {l1_height} output={:?}",
            circuit_output
        );

        assert_eq!(circuit_output.lcp_state_root, result.lcp_state_root);

        // Only save after the proof is generated
        self.storage_manager.finalize_storage(result.change_set);

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

    async fn prove(
        &self,
        light_client_elf: Vec<u8>,
        circuit_input: LightClientCircuitInput<<Da as DaService>::Spec>,
        assumptions: Vec<Vec<u8>>,
    ) -> Result<Proof, anyhow::Error> {
        let data = ProofData {
            input: borsh::to_vec(&circuit_input)?,
            assumptions,
            elf: light_client_elf,
        };
        self.prover_service.prove(data, ReceiptType::Groth16).await
    }
}
