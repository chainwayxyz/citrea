use std::net::SocketAddr;

use borsh::BorshSerialize;
use jsonrpsee::RpcModule;
use sov_db::ledger_db::{LedgerDB, SlotCommit};
use sov_modules_stf_blueprint::{Batch, RawTx};
use sov_rollup_interface::da::{BlobReaderTrait, BlockHeaderTrait, DaSpec};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::storage::StorageManager;
use sov_rollup_interface::zk::ZkvmHost;
use tokio::sync::oneshot;
use tracing::{debug, info};

use crate::config::SoftConfirmationClientRpcConfig;
use crate::soft_confirmation_client::SoftConfirmationClient;
use crate::verifier::StateTransitionVerifier;
use crate::{ProverService, RunnerConfig};
type StateRoot<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::StateRoot;
type InitialState<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::GenesisParams;

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
    soft_confirmation_client: Option<SoftConfirmationClient>,
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
        scc_config: Option<SoftConfirmationClientRpcConfig>,
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
        let last_slot_processed_before_shutdown = item_numbers.slot_number - 1;
        let start_height = runner_config.start_height + last_slot_processed_before_shutdown;

        let soft_confirmation_client = match scc_config {
            Some(scc_config) => Some(SoftConfirmationClient::new(
                scc_config.start_height,
                scc_config.scc_url,
            )),
            None => None,
        };

        Ok(Self {
            start_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: prev_state_root,
            listen_address,
            prover_service,
            soft_confirmation_client,
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

    /// Processes sequence
    /// gets a blob of txs as parameter
    pub async fn process(&mut self, blob: &[u8]) -> Result<(), anyhow::Error> {
        println!("blob: {:?}", blob);
        let pre_state = self.storage_manager.get_native_storage();
        println!("got pre_state ");
        let filtered_block: <Da as DaService>::FilteredBlock =
            self.da_service.get_block_at(2u64).await?;
        println!("got filtered_block ");
        let blobz = self.da_service.convert_to_transaction(blob).unwrap();
        println!("got blobz ");

        info!(
            "sequencer={} blob_hash=0x{}",
            blobz.0.sender(),
            hex::encode(blobz.0.hash())
        );

        let slot_result = self.stf.apply_slot(
            &self.state_root,
            pre_state,
            Default::default(),
            filtered_block.header(),              // mock this
            &filtered_block.validity_condition(), // mock this
            &mut vec![blobz.0],
        );
        debug!("slot_result: {:?}", slot_result.batch_receipts.len());
        println!("slot_result: {:?}", slot_result.batch_receipts.len());

        let mut data_to_commit = SlotCommit::new(filtered_block.clone());
        for receipt in slot_result.batch_receipts {
            data_to_commit.add_batch(receipt);
        }
        println!("added batch");
        let next_state_root = slot_result.state_root;
        let pre_head_slot = self.ledger_db.get_head_slot()?;
        println!("pre_head_slot: {:?}", pre_head_slot);
        self.ledger_db.commit_slot(data_to_commit)?;
        let head_slot = self.ledger_db.get_head_slot()?;
        println!("head_slot: {:?}", head_slot);
        println!("Committed slot");
        println!("state_root: {:?}", next_state_root);
        self.state_root = next_state_root;

        Ok(())
    }

    /// Runs the rollup.
    pub async fn run_in_process(&mut self) -> Result<(), anyhow::Error> {
        let client = match &self.soft_confirmation_client {
            Some(client) => client,
            None => {
                return Err(anyhow::anyhow!(
                    "Soft Confirmation Client is not initialized"
                ))
            }
        };

        let mut height = self.start_height;
        loop {
            let tx = client.get_sov_tx(height).await;

            if tx.is_err() {
                info!("STFRunner - Height: {} not found", height);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }

            let batch = Batch {
                txs: vec![RawTx { data: tx.unwrap() }],
            };

            let new_blobs = self
                .da_service
                .convert_to_transaction(&batch.try_to_vec().unwrap())
                .unwrap();

            debug!("Requesting data for height {}", height,);

            // TODO: Change here
            let filtered_block = self.da_service.get_block_at(2).await?;

            let blob_with_sender: <<Da as DaService>::Spec as DaSpec>::BlobTransaction =
                new_blobs.0;

            let blob_sender_hash = blob_with_sender.hash();

            info!(
                "Extracted blob-tx {} with length {} at height {}",
                hex::encode(&blob_sender_hash),
                blob_with_sender.total_len(),
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
                &mut vec![blob_with_sender],
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

            let next_state_root = slot_result.state_root;

            self.ledger_db.commit_slot(data_to_commit)?;
            self.state_root = next_state_root;

            info!(
                "New State Root after blob {:?} is: {:?}",
                hex::encode(blob_sender_hash),
                self.state_root.as_ref()
            );
            height += 1;
        }
    }
}
