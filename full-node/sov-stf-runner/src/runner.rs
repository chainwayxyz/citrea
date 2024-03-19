use std::collections::VecDeque;
use std::marker::PhantomData;
use std::net::SocketAddr;

use anyhow::bail;
use borsh::de::BorshDeserialize;
use jsonrpsee::core::Error;
use jsonrpsee::RpcModule;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sequencer_client::SequencerClient;
use sov_db::ledger_db::{LedgerDB, SlotCommit};
use sov_db::schema::types::{BatchNumber, SlotNumber, StoredSoftBatch};
use sov_modules_api::Context;
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_rollup_interface::da::DaData::SequencerCommitment;
use sov_rollup_interface::da::{BlobReaderTrait, BlockHeaderTrait, DaData, DaSpec};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::{DaService, SlotData};
pub use sov_rollup_interface::stf::BatchReceipt;
use sov_rollup_interface::stf::{SoftBatchReceipt, StateTransitionFunction};
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::{Zkvm, ZkvmHost};
use tokio::sync::oneshot;
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, error, info};

use crate::verifier::StateTransitionVerifier;
use crate::{ProverService, RunnerConfig};

type StateRoot<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::StateRoot;
type GenesisParams<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::GenesisParams;

const CONNECTION_INTERVALS: &[u64] = &[0, 1, 2, 5, 10, 15, 30, 60];
const RETRY_INTERVAL: &[u64] = &[1, 5];
const RETRY_SLEEP: u64 = 2;

/// Combines `DaService` with `StateTransitionFunction` and "runs" the rollup.
pub struct StateTransitionRunner<Stf, Sm, Da, Vm, Ps, C>
where
    Da: DaService,
    Vm: ZkvmHost,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Stf: StateTransitionFunction<Vm, Da::Spec, Condition = <Da::Spec as DaSpec>::ValidityCondition>
        + StfBlueprintTrait<C, Da::Spec, Vm>,
    Ps: ProverService,
    C: Context,
{
    start_height: u64,
    da_service: Da,
    stf: Stf,
    storage_manager: Sm,
    /// made pub so that sequencer can clone it
    pub ledger_db: LedgerDB,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    listen_address: SocketAddr,
    #[allow(dead_code)]
    prover_service: Option<Ps>,
    sequencer_client: Option<SequencerClient>,
    sequencer_pub_key: Vec<u8>,
    phantom: std::marker::PhantomData<C>,
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

/// How [`StateTransitionRunner`] is initialized
pub enum InitVariant<Stf: StateTransitionFunction<Vm, Da>, Vm: Zkvm, Da: DaSpec> {
    /// From give state root
    Initialized(Stf::StateRoot),
    /// From empty state root
    Genesis {
        /// Genesis block header should be finalized at init moment
        block_header: Da::BlockHeader,
        /// Genesis params for Stf::init
        genesis_params: GenesisParams<Stf, Vm, Da>,
    },
}

impl<Stf, Sm, Da, Vm, Ps, C> StateTransitionRunner<Stf, Sm, Da, Vm, Ps, C>
where
    Da: DaService<Error = anyhow::Error> + Clone + Send + Sync + 'static,
    Vm: ZkvmHost,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Stf: StateTransitionFunction<
            Vm,
            Da::Spec,
            Condition = <Da::Spec as DaSpec>::ValidityCondition,
            PreState = Sm::NativeStorage,
            ChangeSet = Sm::NativeChangeSet,
        > + StfBlueprintTrait<C, Da::Spec, Vm>,
    C: Context,
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
        mut storage_manager: Sm,
        init_variant: InitVariant<Stf, Vm, Da::Spec>,
        prover_service: Option<Ps>,
        sequencer_client: Option<SequencerClient>,
        sequencer_pub_key: Vec<u8>,
    ) -> Result<Self, anyhow::Error> {
        let rpc_config = runner_config.rpc_config;

        let prev_state_root = match init_variant {
            InitVariant::Initialized(state_root) => {
                debug!("Chain is already initialized. Skipping initialization.");
                state_root
            }
            InitVariant::Genesis {
                block_header,
                genesis_params: params,
            } => {
                info!(
                    "No history detected. Initializing chain on block_header={:?}...",
                    block_header
                );
                let storage = storage_manager.create_storage_on_l2_height(0)?;
                let (genesis_root, initialized_storage) = stf.init_chain(storage, params);
                storage_manager.save_change_set_l2(0, initialized_storage)?;
                storage_manager.finalize_l2(0)?;
                info!(
                    "Chain initialization is done. Genesis root: 0x{}",
                    hex::encode(genesis_root.as_ref()),
                );
                genesis_root
            }
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
            sequencer_pub_key,
            phantom: std::marker::PhantomData,
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

    /// Runs the rollup.
    pub async fn run_in_process(&mut self) -> Result<(), anyhow::Error> {
        let Some(client) = &self.sequencer_client else {
            return Err(anyhow::anyhow!("Sequencer Client is not initialized"));
        };

        let mut seen_block_headers: VecDeque<<Da::Spec as DaSpec>::BlockHeader> = VecDeque::new();
        let mut seen_receipts: VecDeque<_> = VecDeque::new();
        let mut height = self.start_height;
        info!("Starting to sync from height {}", height);

        let mut last_connection_error = Instant::now();
        let mut last_parse_error = Instant::now();

        let mut connection_index = 0;
        let mut retry_index = 0;

        loop {
            let soft_batch = client.get_soft_batch::<Da::Spec>(height).await;

            if soft_batch.is_err() {
                let x = soft_batch.unwrap_err();
                match x.downcast_ref::<jsonrpsee::core::Error>() {
                    Some(Error::Transport(e)) => {
                        debug!("Soft Batch: connection error during RPC call: {:?}", e);
                        Self::log_error(
                            &mut last_connection_error,
                            CONNECTION_INTERVALS,
                            &mut connection_index,
                            format!("Soft Batch: connection error during RPC call: {:?}", e)
                                .as_str(),
                        );
                        sleep(Duration::from_secs(RETRY_SLEEP)).await;
                        continue;
                    }
                    _ => {
                        anyhow::bail!("Soft Batch: unknown error from RPC call: {:?}", x);
                    }
                }
            }

            let soft_batch = match soft_batch.unwrap() {
                Some(soft_batch) => soft_batch,
                None => {
                    debug!(
                        "Soft Batch: no batch at height {}, retrying in {} seconds",
                        height, RETRY_SLEEP
                    );
                    Self::log_error(
                        &mut last_parse_error,
                        RETRY_INTERVAL,
                        &mut retry_index,
                        "No soft batch published".to_string().as_str(),
                    );
                    sleep(Duration::from_secs(RETRY_SLEEP)).await;
                    continue;
                }
            };

            // TODO: for a node, the da block at slot_height might not have been finalized yet
            // should wait for it to be finalized
            let filtered_block = self
                .da_service
                .get_block_at(soft_batch.da_slot_height)
                .await?;

            // TODO: when legit blocks are implemented use below to
            // check for reorgs
            // Checking if reorg happened or not.
            // if let Some(prev_block_header) = seen_block_headers.back() {
            //     if prev_block_header.hash() != filtered_block.header().prev_hash() {
            //         tracing::warn!("Block at height={} does not belong in current chain. Chain has forked. Traversing backwards", height);
            //         while let Some(seen_block_header) = seen_block_headers.pop_back() {
            //             seen_receipts.pop_back();
            //             let block = self
            //                 .da_service
            //                 .get_block_at(seen_block_header.height())
            //                 .await?;
            //             if block.header().prev_hash() == seen_block_header.prev_hash() {
            //                 height = seen_block_header.height();
            //                 filtered_block = block;
            //                 break;
            //             }
            //         }
            //         tracing::info!("Resuming execution on height={}", height);
            //     }
            // }

            // Merkle root hash - L1 start height - L1 end height
            // TODO: How to confirm this is what we submit - use?
            // TODO: Add support for multiple commitments in a single block
            let (da_data, da_errors): (Vec<_>, Vec<_>) = self
                .da_service
                .extract_relevant_blobs(&filtered_block)
                .into_iter()
                .map(|mut tx| DaData::try_from_slice(tx.full_data()))
                .partition(Result::is_ok);

            if !da_errors.is_empty() {
                tracing::warn!(
                    "Found broken DA data in block 0x{}: {:?}",
                    hex::encode(filtered_block.hash()),
                    da_errors
                );
            }

            let sequencer_commitments: Vec<_> = da_data
                .into_iter()
                .filter_map(|d| match d {
                    Ok(SequencerCommitment(seq_com)) => Some(seq_com),
                    _ => None,
                })
                .collect();

            // TODO here we can support multiple commitments but for now let's take the last one.
            let sequencer_commitment = sequencer_commitments.iter().last();

            if sequencer_commitment.is_some() {
                let sequencer_commitment = sequencer_commitment.unwrap();

                let start_l1_height = self
                    .da_service
                    .get_block_by_hash(sequencer_commitment.l1_start_block_hash)
                    .await
                    .unwrap()
                    .header()
                    .height();

                let end_l1_height = self
                    .da_service
                    .get_block_by_hash(sequencer_commitment.l1_end_block_hash)
                    .await
                    .unwrap()
                    .header()
                    .height();

                let (start_l2_height, _) = self
                    .ledger_db
                    .get_l2_range_by_l1_height(SlotNumber(start_l1_height))
                    .expect("Sequencer: Failed to get L1 L2 connection")
                    .unwrap();

                let (_, end_l2_height) = self
                    .ledger_db
                    .get_l2_range_by_l1_height(SlotNumber(start_l1_height))
                    .expect("Sequencer: Failed to get L1 L2 connection")
                    .unwrap();

                let range_end = BatchNumber(end_l2_height.0 + 1);
                // Traverse each item's field of vector of transactions, put them in merkle tree
                // and compare the root with the one from the ledger
                let stored_soft_batches: Vec<StoredSoftBatch> = self
                    .ledger_db
                    .get_soft_batch_range(&(start_l2_height..range_end))
                    .unwrap();

                let soft_batches_tree = MerkleTree::<Sha256>::from_leaves(
                    stored_soft_batches
                        .iter()
                        .map(|x| x.hash)
                        .collect::<Vec<_>>()
                        .as_slice(),
                );

                if soft_batches_tree.root() != Some(sequencer_commitment.merkle_root) {
                    tracing::warn!(
                        "Merkle root mismatch - expected 0x{} but got 0x{}",
                        hex::encode(soft_batches_tree.root().unwrap()),
                        hex::encode(sequencer_commitment.merkle_root)
                    );
                }

                for i in start_l1_height..=end_l1_height {
                    self.ledger_db
                        .put_soft_confirmation_status(
                            SlotNumber(i),
                            SoftConfirmationStatus::Finalized,
                        )
                        .unwrap_or_else(|_| {
                            panic!(
                                "Failed to put soft confirmation status in the ledger db {}",
                                i
                            )
                        });
                }
            }

            info!(
                "Running soft confirmation batch #{} with hash: 0x{} on DA block #{}",
                height,
                hex::encode(soft_batch.hash),
                filtered_block.header().height()
            );

            let mut data_to_commit = SlotCommit::new(filtered_block.clone());

            let pre_state = self.storage_manager.create_storage_on_l2_height(height)?;

            let slot_result = self.stf.apply_soft_batch(
                self.sequencer_pub_key.as_slice(),
                // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1247): incorrect pre-state root in case of re-org
                &self.state_root,
                pre_state,
                Default::default(),
                filtered_block.header(),
                &filtered_block.validity_condition(),
                &mut soft_batch.clone().into(),
            );

            for receipt in slot_result.batch_receipts {
                data_to_commit.add_batch(receipt);
            }

            // let (inclusion_proof, completeness_proof) = self
            //     .da_service
            //     .get_extraction_proof(&filtered_block, vec_blobs.as_slice())
            //     .await;

            // let _transition_data: StateTransitionData<Stf::StateRoot, Stf::Witness, Da::Spec> =
            //     StateTransitionData {
            //         // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1247): incorrect pre-state root in case of re-org
            //         initial_state_root: self.state_root.clone(),
            //         final_state_root: slot_result.state_root.clone(),
            //         da_block_header: filtered_block.header().clone(),
            //         inclusion_proof,
            //         completeness_proof,
            //         blobs: vec_blobs,
            //         state_transition_witness: slot_result.witness,
            //     };

            self.storage_manager
                .save_change_set_l2(height, slot_result.change_set)?;

            // ----------------
            // Create ZK proof.
            // {
            //     let header_hash = transition_data.da_block_header.hash();
            //     self.prover_service.submit_witness(transition_data).await;
            //     // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1185):
            //     //   This section will be moved and called upon block finalization once we have fork management ready.
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
            //             // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1185): Add timeout handling.
            //             Ok(ProofSubmissionStatus::ProofGenerationInProgress) => {
            //                 tokio::time::sleep(tokio::time::Duration::from_millis(100)).await
            //             }
            //             // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1185): Add handling for DA submission errors.
            //             Err(e) => panic!("{:?}", e),
            //         }
            //     }
            // }

            let batch_receipt = data_to_commit.batch_receipts()[0].clone();

            let next_state_root = slot_result.state_root;

            // Check if post state root is the same as the one in the soft batch
            if next_state_root.as_ref().to_vec() != soft_batch.post_state_root {
                bail!("Post state root mismatch")
            }

            let soft_batch_receipt = SoftBatchReceipt::<_, _, Da::Spec> {
                pre_state_root: self.state_root.as_ref().to_vec(),
                post_state_root: next_state_root.as_ref().to_vec(),
                phantom_data: PhantomData::<u64>,
                batch_hash: batch_receipt.batch_hash,
                da_slot_hash: filtered_block.header().hash(),
                da_slot_height: filtered_block.header().height(),
                tx_receipts: batch_receipt.tx_receipts,
                soft_confirmation_signature: soft_batch.soft_confirmation_signature,
                pub_key: soft_batch.pub_key,
                l1_fee_rate: soft_batch.l1_fee_rate,
            };

            self.ledger_db.commit_soft_batch(soft_batch_receipt, true)?;
            self.ledger_db
                .extend_l2_range_of_l1_slot(
                    SlotNumber(filtered_block.header().height()),
                    BatchNumber(height),
                )
                .expect("Sequencer: Failed to set L1 L2 connection");

            self.state_root = next_state_root;
            seen_receipts.push_back(data_to_commit);
            seen_block_headers.push_back(filtered_block.header().clone());

            info!(
                "New State Root after soft confirmation #{} is: {:?}",
                height, self.state_root
            );

            // ----------------
            // Finalization. Done after seen block for proper handling of instant finality
            // Can be moved to another thread to improve throughput
            let last_finalized = self.da_service.get_last_finalized_block_header().await?;
            // For safety we finalize blocks one by one
            tracing::info!(
                "Last finalized header height is {}, ",
                last_finalized.height()
            );
            // Checking all seen blocks, in case if there was delay in getting last finalized header.
            // while let Some(earliest_seen_header) = seen_block_headers.front() {
            //     tracing::debug!(
            //         "Checking seen header height={}",
            //         earliest_seen_header.height()
            //     );
            //     if earliest_seen_header.height() <= last_finalized.height() {
            //         tracing::debug!(
            //             "Finalizing seen header height={}",
            //             earliest_seen_header.height()
            //         );

            //         continue;
            //     }

            //     break;
            // }
            // self.storage_manager.finalize(earliest_seen_header)?;
            seen_block_headers.pop_front();
            let receipts = seen_receipts.pop_front().unwrap();
            self.ledger_db.commit_slot(receipts)?;
            self.storage_manager.finalize_l2(height)?;

            height += 1;
        }
    }

    /// Allows to read current state root
    pub fn get_state_root(&self) -> &Stf::StateRoot {
        &self.state_root
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
