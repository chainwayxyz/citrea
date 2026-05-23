//! Data Availability (DA) block handling for the light client prover
//!
//! This module handles the processing of DA layer blocks for light client proof generation
//! and maintaining the light client state.
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::sync_l1;
use citrea_common::utils::shutdown_requested;
use citrea_common::{LightClientProverConfig, StartVariant};
use prover_services::{ParallelProverService, ProofData, ProofWithDuration};
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
use sov_rollup_interface::zk::{ReceiptType, ZkvmHost};
use sov_rollup_interface::Network;
use tokio::select;
use tokio::sync::{Mutex, Notify};
use tracing::{error, info, instrument};

use crate::circuit::initial_values::InitialValueProvider;
use crate::circuit::LightClientProofCircuit;
use crate::input_builder::{build_circuit_input_from_l1_block, PreparedLightClientCircuitInput};
use crate::l1_block_state::validate_live_l1_height;
use crate::metrics::LIGHT_CLIENT_METRICS as LPM;

/// Handler for processing L1 blocks and the relevant transactions within them.
///
/// This component is responsible for processing finalized L1 blocks, running the light client proof circuit logic per L1 block,
/// keeping track of the light client state, and generating proofs light client proofs.
pub struct L1BlockHandler<Vm, Da, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm + 'static,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone,
    Network: InitialValueProvider<Da::Spec>,
{
    /// The Citrea network this handler is running on
    network: Network,
    /// Prover configuration
    prover_config: LightClientProverConfig,
    /// Prover service to submit proof data and handle proving sessions
    prover_service: Arc<ParallelProverService<Da, Vm>>,
    /// Manager for light client prover storage
    storage_manager: ProverStorageManager,
    /// Database for ledger operations
    ledger_db: DB,
    /// Data availability service instance
    da_service: Arc<Da>,
    /// Code commitments for light client proof circuit
    light_client_proof_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
    /// ELF binaries for light client proof circuit
    light_client_proof_elfs: HashMap<SpecId, Vec<u8>>,
    /// Cache for L1 block data
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    /// Queue of L1 blocks waiting to be processed
    queued_l1_blocks: Arc<Mutex<VecDeque<<Da as DaService>::FilteredBlock>>>,
    /// Manager for backup operations
    backup_manager: Arc<BackupManager>,
    /// Light client proof circuit logic
    circuit: LightClientProofCircuit<ProverStorage, Da::Spec, Vm>,
}

impl<Vm, Da, DB> L1BlockHandler<Vm, Da, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone,
    Network: InitialValueProvider<Da::Spec>,
{
    /// Creates a new instance of the L1BlockHandler
    /// # Arguments
    /// * `network` - The Citrea network this handler is running on
    /// * `prover_config` - Prover configuration
    /// * `prover_service` - Prover service to submit proof data and handle proving sessions
    /// * `storage_manager` - Manager for light client prover storage
    /// * `ledger_db` - Database for ledger operations
    /// * `da_service` - Data availability service instance
    /// * `light_client_proof_code_commitments` - Code commitments for light client proof circuit
    /// * `light_client_proof_elfs` - ELF binaries for light client proof circuit
    /// * `backup_manager` - Manager for backup operations
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
            prover_config,
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

    /// Starts the L1 block handler to process L1 blocks and generate proofs.
    ///
    /// This method continuously:
    /// 1. Syncs new L1 blocks from the DA layer
    /// 2. Processes queued blocks to generate light client proofs and move the light client state forward
    ///
    /// # Arguments
    /// * `last_l1_height_scanned` - `StartVariant` to start syncing from
    /// * `shutdown_signal` - Signal to gracefully shut down
    #[instrument(name = "L1BlockHandler", skip_all)]
    pub async fn run(
        mut self,
        last_l1_height_scanned: StartVariant,
        mut shutdown_signal: GracefulShutdown,
    ) {
        let start_l1_height = last_l1_height_scanned.start_height();
        let notifier = Arc::new(Notify::new());

        let l1_sync_worker = sync_l1(
            start_l1_height,
            self.da_service.clone(),
            self.queued_l1_blocks.clone(),
            self.l1_block_cache.clone(),
            notifier.clone(),
        );
        tokio::pin!(l1_sync_worker);

        let backup_manager = self.backup_manager.clone();
        tokio::time::sleep(Duration::from_secs(1)).await; // Gives time for queue to fill up on startup
        loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    info!("Shutting down L1BlockHandler");
                    return;
                }
                _ = &mut l1_sync_worker => {},
                _ = notifier.notified() => {
                    let _l1_guard = backup_manager.start_l1_processing().await;
                    if let Err(e) = self.process_queued_l1_blocks(&shutdown_signal).await {
                        error!("Could not process queued L1 blocks and generate proof: {:?}", e);
                    }
                },
            }
        }
    }

    /// Processes L1 blocks waiting in the queue.
    async fn process_queued_l1_blocks(
        &mut self,
        shutdown_signal: &GracefulShutdown,
    ) -> Result<(), anyhow::Error> {
        loop {
            if shutdown_requested(shutdown_signal) {
                info!("Shutting down L1BlockHandler");
                return Ok(());
            }

            let Some(l1_block) = self.queued_l1_blocks.lock().await.front().cloned() else {
                break;
            };
            self.process_l1_block(l1_block).await?;
            self.queued_l1_blocks.lock().await.pop_front();
        }

        Ok(())
    }

    /// Processes a single L1 block.
    ///
    /// # Arguments
    /// * `l1_block` - The L1 block to process
    ///
    /// This method:
    /// 1. Runs the L1 block of the light client proof circuit to generate a witness, and gets the updates to the JMT state.
    /// 2. Prepares the light client circuit input and calls `Self::prove` to generate a proof for the L1 block.
    /// 3. Asserts that the state update's state root matches the one in the circuit output, and finalizes the storage.
    async fn process_l1_block(&mut self, l1_block: Da::FilteredBlock) -> anyhow::Result<()> {
        let start_l1_block_processing = Instant::now();
        let l1_hash = l1_block.header().hash().into();
        let l1_height = l1_block.header().height();

        // Set the l1 height of the l1 hash
        self.ledger_db
            .set_l1_height_of_l1_hash(l1_hash, l1_height)
            .expect("Setting l1 height of l1 hash in ledger db");

        let storage = self.committable_storage_for_live_l1_block(l1_height)?;
        let PreparedLightClientCircuitInput {
            spec_id,
            circuit_input,
            lcp_state_root,
            last_l2_height,
            change_set,
            last_sequencer_commitment_index,
        } = build_circuit_input_from_l1_block::<Da, DB, Vm>(
            self.network,
            &self.prover_config,
            self.da_service.as_ref(),
            &self.ledger_db,
            &self.light_client_proof_code_commitments,
            &self.circuit,
            &l1_block,
            storage,
        )?;
        let light_client_elf = self
            .light_client_proof_elfs
            .get(&spec_id)
            .expect("Fork should have a guest code attached")
            .clone();

        let proof_with_duration = self.prove(light_client_elf, circuit_input, vec![]).await?;
        let proof = proof_with_duration.proof;

        let circuit_output = Vm::extract_output::<LightClientCircuitOutput>(&proof)
            .expect("Should deserialize valid proof");

        tracing::info!(
            "Generated proof for L1 block: {l1_height} output={:?}",
            circuit_output
        );

        assert_eq!(circuit_output.lcp_state_root, lcp_state_root);

        // Only save after the proof is generated
        self.storage_manager.finalize_storage(change_set);

        let stored_proof_output = StoredLightClientProofOutput::from(circuit_output);

        self.ledger_db.insert_light_client_proof_data_by_l1_height(
            l1_height,
            proof,
            stored_proof_output,
            proof_with_duration.info,
        )?;

        LPM.set_lcp_proving_time(proof_with_duration.duration);

        self.ledger_db
            .set_last_scanned_l1_height(SlotNumber(l1_block.header().height()))
            .expect("Saving last scanned l1 height to ledger db");

        LPM.current_l1_block.set(l1_height as f64);
        LPM.highest_proven_index
            .set(last_sequencer_commitment_index as f64);
        LPM.highest_proven_l2_height.set(last_l2_height as f64);

        LPM.set_scan_l1_block_duration(
            Instant::now()
                .saturating_duration_since(start_l1_block_processing)
                .as_secs_f64(),
        );

        Ok(())
    }

    /// Creates committable LCP JMT pre-state for the live next L1 block.
    fn committable_storage_for_live_l1_block(
        &self,
        l1_height: u64,
    ) -> anyhow::Result<ProverStorage> {
        let initial_da_height = self.prover_config.initial_da_height;
        let last_scanned_l1_height = self.ledger_db.get_last_scanned_l1_height()?.map(|h| h.0);
        validate_live_l1_height(initial_da_height, last_scanned_l1_height, l1_height)?;

        Ok(self.storage_manager.create_storage_for_next_l2_height())
    }

    /// This method submits the circuit input and ELF binary to the prover service
    /// to generates a proof for the light client circuit.
    /// # Arguments
    /// * `light_client_elf` - The ELF binary for the light client proof circuit
    /// * `circuit_input` - The input for the light client circuit
    /// * `assumptions` - Assumptions used in the proving process
    ///
    /// # Returns
    /// A proof, in bytes, for the light client circuit.
    async fn prove(
        &self,
        light_client_elf: Vec<u8>,
        circuit_input: LightClientCircuitInput<<Da as DaService>::Spec>,
        assumptions: Vec<Vec<u8>>,
    ) -> Result<ProofWithDuration, anyhow::Error> {
        let data = ProofData {
            input: borsh::to_vec(&circuit_input)?,
            assumptions,
            elf: light_client_elf,
        };
        self.prover_service.prove(data, ReceiptType::Groth16).await
    }
}
