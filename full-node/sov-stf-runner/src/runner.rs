use std::net::SocketAddr;

use borsh::BorshSerialize;
use jsonrpsee::core::Error;
use jsonrpsee::RpcModule;
use sequencer_client::SequencerClient;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::{LedgerDB, SlotCommit};
use sov_db::schema::types::{BatchNumber, StoredSoftBatch};
use sov_modules_stf_blueprint::{Batch, RawTx};
use sov_rollup_interface::da::{BlobReaderTrait, BlockHeaderTrait, DaSpec};

use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::stf::{SoftBatchReceipt, StateTransitionFunction};
use sov_rollup_interface::storage::StorageManager;
use sov_rollup_interface::zk::ZkvmHost;
use tokio::sync::oneshot;
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::verifier::StateTransitionVerifier;
use crate::{ProverService, RunnerConfig};
type StateRoot<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::StateRoot;
type InitialState<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::GenesisParams;

const CONNECTION_INTERVALS: &[u64] = &[0, 1, 2, 5, 10, 15, 30, 60];
const PARSE_INTERVALS: &[u64] = &[0, 1, 5];

/// Represents the block template that is used to create a block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockTemplate {
    /// DA block to build on
    pub da_slot_height: u64,
    /// Transactions to include in the block
    pub txs: Vec<Vec<u8>>,
}

/// Combines `DaService` with `StateTransitionFunction` and "runs" the rollup.
pub struct StateTransitionRunner<Stf, Sm, Da, Vm, Ps>
where
    Da: DaService,
    Vm: ZkvmHost,
    Sm: StorageManager,
    Stf: StateTransitionFunction<Vm, Da::Spec, Condition = <Da::Spec as DaSpec>::ValidityCondition>,
    Ps: ProverService,
{
    start_height: u64,
    da_service: Da,
    stf: Stf,
    storage_manager: Sm,
    ledger_db: LedgerDB,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    listen_address: SocketAddr,
    prover_service: Ps,
    sequencer_client: Option<SequencerClient>,
}

/// Represents the possible modes of execution for a zkVM program
pub enum ProofGenConfig<Stf, Da: DaService, Vm: ZkvmHost>
where
    Stf: StateTransitionFunction<Vm::Guest, Da::Spec>,
{
    /// Skips proving.
    Skip,
    /// The simulator runs the rollup verifier logic without even emulating the zkVM
    Simulate(StateTransitionVerifier<Stf, Da::Verifier, Vm::Guest>),
    /// The executor runs the rollup verification logic in the zkVM, but does not actually
    /// produce a zk proof
    Execute,
    /// The prover runs the rollup verification logic in the zkVM and produces a zk proof
    Prover,
}

impl<Stf, Sm, Da, Vm, Ps> StateTransitionRunner<Stf, Sm, Da, Vm, Ps>
where
    Da: DaService<Error = anyhow::Error> + Clone + Send + Sync + 'static,
    Vm: ZkvmHost,
    Sm: StorageManager,
    Stf: StateTransitionFunction<
        Vm,
        Da::Spec,
        Condition = <Da::Spec as DaSpec>::ValidityCondition,
        PreState = Sm::NativeStorage,
        ChangeSet = Sm::NativeChangeSet,
    >,

    Ps: ProverService<StateRoot = Stf::StateRoot, Witness = Stf::Witness, DaService = Da>,
{
    /// Creates a new `StateTransitionRunner`.
    ///
    /// If a previous state root is provided, uses that as the starting point
    /// for execution. Otherwise, initializes the chain using the provided
    /// genesis config.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner_config: RunnerConfig,
        da_service: Da,
        ledger_db: LedgerDB,
        stf: Stf,
        storage_manager: Sm,
        prev_state_root: Option<StateRoot<Stf, Vm, Da::Spec>>,
        genesis_config: InitialState<Stf, Vm, Da::Spec>,
        prover_service: Ps,
        sequencer_client: Option<SequencerClient>,
    ) -> Result<Self, anyhow::Error> {
        let rpc_config = runner_config.rpc_config;

        let prev_state_root = if let Some(prev_state_root) = prev_state_root {
            // Check if the rollup has previously been initialized
            debug!("Chain is already initialized. Skipping initialization.");
            prev_state_root
        } else {
            info!("No history detected. Initializing chain...");
            let genesis_state = storage_manager.get_native_storage();
            let (genesis_root, _) = stf.init_chain(genesis_state, genesis_config);
            info!(
                "Chain initialization is done. Genesis root: 0x{}",
                hex::encode(genesis_root.as_ref())
            );
            genesis_root
        };

        let listen_address = SocketAddr::new(rpc_config.bind_host.parse()?, rpc_config.bind_port);

        // Start the main rollup loop
        let item_numbers = ledger_db.get_next_items_numbers();
        let last_soft_batch_processed_before_shutdown = item_numbers.soft_batch_number;

        let start_height = last_soft_batch_processed_before_shutdown;

        Ok(Self {
            start_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: prev_state_root,
            listen_address,
            prover_service,
            sequencer_client,
        })
    }

    /// Starts a RPC server with provided rpc methods.
    pub async fn start_rpc_server(
        &self,
        methods: RpcModule<()>,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) {
        let listen_address = self.listen_address;
        let _handle = tokio::spawn(async move {
            let server = jsonrpsee::server::ServerBuilder::default()
                .build([listen_address].as_ref())
                .await
                .unwrap();

            let bound_address = server.local_addr().unwrap();
            if let Some(channel) = channel {
                channel.send(bound_address).unwrap();
            }
            info!("Starting RPC server at {} ", &bound_address);

            let _server_handle = server.start(methods);
            futures::future::pending::<()>().await;
        });
    }

    /// Returns the head soft batch
    pub fn get_head_soft_batch(&self) -> anyhow::Result<Option<(BatchNumber, StoredSoftBatch)>> {
        self.ledger_db.get_head_soft_batch()
    }

    /// Processes sequence
    /// gets a blob of txs as parameter
    pub async fn process(&mut self, block_template: BlockTemplate) -> Result<(), anyhow::Error> {
        let pre_state = self.storage_manager.get_native_storage();

        let (txs, da_slot_height) = (block_template.txs, block_template.da_slot_height);

        let filtered_block = self.da_service.get_block_at(da_slot_height).await?;

        let batch = Batch {
            txs: txs.iter().map(|tx| RawTx { data: tx.clone() }).collect(),
        };

        let (blob, _signature) = self
            .da_service
            .convert_rollup_batch_to_da_blob(&batch.try_to_vec().unwrap())
            .unwrap();

        info!(
            "sequencer={} blob_hash=0x{}",
            blob.sender(),
            hex::encode(blob.hash())
        );

        let slot_result = self.stf.apply_slot(
            &self.state_root,
            pre_state,
            Default::default(),
            filtered_block.header(),
            &filtered_block.validity_condition(),
            &mut vec![blob],
        );

        info!(
            "State root after applying slot: {:?}",
            slot_result.state_root
        );

        let mut data_to_commit = SlotCommit::new(filtered_block.clone());
        for receipt in slot_result.batch_receipts {
            data_to_commit.add_batch(receipt);
        }

        let batch_receipt = data_to_commit.batch_receipts()[0].clone();

        let soft_batch_receipt = SoftBatchReceipt::<_, _, Da::Spec> {
            inner: batch_receipt.inner,
            batch_hash: batch_receipt.batch_hash,
            da_slot_hash: filtered_block.header().hash(),
            da_slot_height: filtered_block.header().height(),
            tx_receipts: batch_receipt.tx_receipts.clone(),
        };

        let next_state_root = slot_result.state_root;
        self.ledger_db
            .commit_soft_batch(soft_batch_receipt, false)?;
        self.state_root = next_state_root;

        Ok(())
    }

    /// Runs the rollup.
    pub async fn run_in_process(&mut self) -> Result<(), anyhow::Error> {
        let client = match &self.sequencer_client {
            Some(client) => client,
            None => return Err(anyhow::anyhow!("Sequencer Client is not initialized")),
        };

        let mut height = self.start_height;
        println!("Starting from height {}", height);

        let mut last_connection_error = Instant::now();
        let mut last_parse_error = Instant::now();

        let mut connection_index = 0;
        let mut parse_index = 0;

        loop {
            let soft_batch = client.get_sov_batch::<Da::Spec>(height).await;

            if soft_batch.is_err() {
                // TODO: Add logs here: https://github.com/chainwayxyz/secret-sovereign-sdk/issues/47

                let x = soft_batch.unwrap_err();
                match x.downcast_ref::<jsonrpsee::core::Error>() {
                    Some(Error::Transport(e)) => {
                        debug!("Connection error during RPC call: {:?}", e);
                        sleep(Duration::from_secs(2)).await;
                        Self::log_error(
                            &mut last_connection_error,
                            CONNECTION_INTERVALS,
                            &mut connection_index,
                            format!("Connection error during RPC call: {:?}", e).as_str(),
                        );
                        continue;
                    }
                    Some(Error::ParseError(e)) => {
                        debug!("Retrying after {} seconds: {:?}", 2, e);
                        sleep(Duration::from_secs(2)).await;
                        Self::log_error(
                            &mut last_parse_error,
                            PARSE_INTERVALS,
                            &mut parse_index,
                            format!("Parse error upon RPC call: {:?}", e).as_str(),
                        );
                        continue;
                    }
                    _ => {
                        anyhow::bail!("Unknown error from RPC call: {:?}", x);
                    }
                }
            }

            let soft_batch = match soft_batch.unwrap() {
                Some(soft_batch) => soft_batch,
                None => {
                    debug!("No soft batch at height {}", height);
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            let batch = Batch {
                txs: soft_batch
                    .txs
                    .unwrap_or_default()
                    .iter()
                    .map(|tx| RawTx { data: tx.clone() })
                    .collect(),
            };

            let new_blobs = self
                .da_service
                .convert_rollup_batch_to_da_blob(&batch.try_to_vec().unwrap())
                .unwrap();

            let filtered_block = self
                .da_service
                .get_block_at(soft_batch.da_slot_height)
                .await?;

            // Check whether da slot hash is the same with the one in the soft batch
            if filtered_block.header().hash() != soft_batch.da_slot_hash {
                warn!(
                    "DA slot hash mismatch: soft batch: {}, da block: {}",
                    hex::encode(soft_batch.da_slot_hash.into()),
                    hex::encode(filtered_block.header().hash().into())
                );
            }

            // 0 is the BlobTransaction
            // 1 is the Signature
            let tx_blob_with_sender: <<Da as DaService>::Spec as DaSpec>::BlobTransaction =
                new_blobs.0;

            let blob_hash = tx_blob_with_sender.hash();

            info!(
                "Extracted blob-tx {} with length {} at height {}",
                hex::encode(blob_hash),
                tx_blob_with_sender.total_len(),
                height,
            );

            let mut data_to_commit = SlotCommit::new(filtered_block.clone());

            let pre_state = self.storage_manager.get_native_storage();
            let slot_result = self.stf.apply_slot(
                &self.state_root,
                pre_state,
                Default::default(),
                filtered_block.header(),
                &filtered_block.validity_condition(),
                &mut vec![tx_blob_with_sender],
            );

            for receipt in slot_result.batch_receipts {
                data_to_commit.add_batch(receipt);
            }

            // let (inclusion_proof, completeness_proof) = self
            //     .da_service
            //     .get_extraction_proof(&filtered_block, &blobs)
            //     .await;

            // let transition_data: StateTransitionData<Stf::StateRoot, Stf::Witness, Da::Spec> =
            //     StateTransitionData {
            //         pre_state_root: self.state_root.clone(),
            //         da_block_header: filtered_block.header().clone(),
            //         inclusion_proof,
            //         completeness_proof,
            //         blobs,
            //         state_transition_witness: slot_result.witness,
            //     };

            // // Create ZKP proof.
            // {
            //     let header_hash = transition_data.da_block_header.hash();
            //     self.prover_service.submit_witness(transition_data).await;
            //     // TODO(#1185): This section will be moved and called upon block finalization once we have fork management ready.
            //     self.prover_service
            //         .prove(header_hash.clone())
            //         .await
            //         .expect("The proof creation should succeed");

            //     loop {
            //         let status = self
            //             .prover_service
            //             .send_proof_to_da(header_hash.clone())
            //             .await;

            //         match status {
            //             Ok(ProofSubmissionStatus::Success) => {
            //                 break;
            //             }
            //             // TODO(#1185): Add timeout handling.
            //             Ok(ProofSubmissionStatus::ProofGenerationInProgress) => {
            //                 tokio::time::sleep(tokio::time::Duration::from_millis(100)).await
            //             }
            //             // TODO(#1185): Add handling for DA submission errors.
            //             Err(e) => panic!("{:?}", e),
            //         }
            //     }
            // }

            let batch_receipt = data_to_commit.batch_receipts()[0].clone();

            let soft_batch_receipt = SoftBatchReceipt::<_, _, Da::Spec> {
                inner: batch_receipt.inner,
                batch_hash: batch_receipt.batch_hash,
                da_slot_hash: filtered_block.header().hash(),
                da_slot_height: filtered_block.header().height(),
                tx_receipts: batch_receipt.tx_receipts.clone(),
            };

            let next_state_root = slot_result.state_root;
            self.ledger_db.commit_soft_batch(soft_batch_receipt, true)?;
            self.state_root = next_state_root;

            info!(
                "New State Root after blob {:?} is: {:?}",
                hex::encode(blob_hash),
                self.state_root
            );
            height += 1;
        }
    }

    /// A basic helper for exponential backoff for error logging.
    pub fn log_error(
        last_error_log: &mut Instant,
        error_log_intervals: &[u64],
        error_interval_index: &mut usize,
        error_msg: &str,
    ) {
        let now = Instant::now();
        if now.duration_since(*last_error_log)
            >= Duration::from_secs(error_log_intervals[*error_interval_index] * 60)
        {
            error!(
                "{} : {} minutes",
                error_msg, error_log_intervals[*error_interval_index]
            );
            *last_error_log = now; // Update the value pointed by the reference
            *error_interval_index = (*error_interval_index + 1).min(error_log_intervals.len() - 1);
        }
    }
}
