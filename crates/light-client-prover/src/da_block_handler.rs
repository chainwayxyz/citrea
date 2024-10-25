use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use borsh::BorshDeserialize;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::get_da_block_at_height;
use citrea_common::LightClientProverConfig;
use sov_db::ledger_db::{LightClientProverLedgerOps, SharedLedgerOps};
use sov_db::schema::types::SlotNumber;
use sov_modules_api::{BlobReaderTrait, DaSpec, Zkvm};
use sov_rollup_interface::da::{BlockHeaderTrait, DaDataLightClient};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::ProverService;
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::input::LightClientCircuitInput;
use crate::output::LightClientCircuitOutput;

pub(crate) struct L1BlockHandler<Vm, Da, Ps, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone,
    Ps: ProverService<Vm>,
{
    _prover_config: LightClientProverConfig,
    prover_service: Arc<Ps>,
    ledger_db: DB,
    da_service: Arc<Da>,
    batch_prover_da_pub_key: Vec<u8>,
    _batch_proof_code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    _light_client_proof_code_commitment: Vm::CodeCommitment,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    queued_l1_blocks: VecDeque<<Da as DaService>::FilteredBlock>,
}

impl<Vm, Da, Ps, DB> L1BlockHandler<Vm, Da, Ps, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<Vm, DaService = Da>,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prover_config: LightClientProverConfig,
        prover_service: Arc<Ps>,
        ledger_db: DB,
        da_service: Arc<Da>,
        batch_prover_da_pub_key: Vec<u8>,
        batch_proof_code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
        light_client_proof_code_commitment: Vm::CodeCommitment,
    ) -> Self {
        Self {
            _prover_config: prover_config,
            prover_service,
            ledger_db,
            da_service,
            batch_prover_da_pub_key,
            _batch_proof_code_commitments_by_spec: batch_proof_code_commitments_by_spec,
            _light_client_proof_code_commitment: light_client_proof_code_commitment,
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

        let mut da_data: Vec<<<Da as DaService>::Spec as DaSpec>::BlobTransaction> = self
            .da_service
            .extract_relevant_blobs_light_client(l1_block);

        let batch_proofs = self.extract_batch_proofs(&mut da_data, l1_hash).await;
        tracing::info!(
            "Block {} has {} batch proofs",
            l1_height,
            batch_proofs.len()
        );

        // Do any kind of ordering etc. on batch proofs here
        // If you do so, don't forget to do the same inside zk

        let circuit_input = self.create_circuit_input(da_data, l1_block).await;

        let circuit_output = self.prove(circuit_input).await?;

        tracing::info!(
            "Generated proof for L1 block: {l1_height} output={:?}",
            circuit_output
        );

        self.ledger_db
            .set_last_scanned_l1_height(SlotNumber(l1_block.header().height()))
            .expect("Saving last scanned l1 height to ledger db");

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

    async fn create_circuit_input(
        &self,
        da_data: Vec<<<Da as DaService>::Spec as DaSpec>::BlobTransaction>,
        l1_block: &Da::FilteredBlock,
    ) -> LightClientCircuitInput<Da::Spec> {
        let (inclusion_proof, completeness_proof) = self
            .da_service
            .get_extraction_proof_light_client(l1_block)
            .await;

        LightClientCircuitInput {
            da_data,
            inclusion_proof,
            completeness_proof,
            da_block_header: l1_block.header().clone(),
            batch_prover_da_pub_key: self.batch_prover_da_pub_key.clone(),
        }
    }

    async fn prove(
        &self,
        circuit_input: LightClientCircuitInput<<Da as DaService>::Spec>,
    ) -> Result<LightClientCircuitOutput, anyhow::Error> {
        let da_slot_hash = circuit_input.da_block_header.hash();
        let prover_service = self.prover_service.as_ref();

        prover_service
            .submit_witness(borsh::to_vec(&circuit_input)?, da_slot_hash.clone())
            .await;

        prover_service.prove(da_slot_hash.clone()).await?;

        let output: LightClientCircuitOutput = prover_service
            .wait_for_proving_and_extract_output(da_slot_hash)
            .await?;

        Ok(output)
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
        // TODO: for a node, the da block at slot_height might not have been finalized yet
        // should wait for it to be finalized
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
