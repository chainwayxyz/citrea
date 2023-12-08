use std::net::SocketAddr;

use borsh::BorshSerialize;
use jsonrpsee::RpcModule;
use sov_db::ledger_db::{LedgerDB, SlotCommit};
use sov_modules_stf_template::{Batch, RawTx};
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::storage::StorageManager;
use sov_rollup_interface::zk::ZkvmHost;
use tokio::sync::oneshot;
use tracing::{debug, info};

use crate::config::SoftConfirmationClient;
use crate::verifier::StateTransitionVerifier;
use crate::{RpcConfig, RunnerConfig};

type StateRoot<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::StateRoot;
type InitialState<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::GenesisParams;

/// Combines `DaService` with `StateTransitionFunction` and "runs" the rollup.
pub struct StateTransitionRunner<Stf, Sm, Da, Vm, V>
where
    Da: DaService,
    Vm: ZkvmHost,
    Sm: StorageManager,
    Stf: StateTransitionFunction<Vm, Da::Spec, Condition = <Da::Spec as DaSpec>::ValidityCondition>,
    V: StateTransitionFunction<Vm::Guest, Da::Spec>,
{
    start_height: u64,
    da_service: Da,
    stf: Stf,
    storage_manager: Sm,
    ledger_db: LedgerDB,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    listen_address: SocketAddr,
    prover: Option<Prover<V, Da, Vm>>,
    zk_storage: V::PreState,
    soft_confirmation_client: SoftConfirmationClient,
}

/// Represents the possible modes of execution for a zkVM program
pub enum ProofGenConfig<Stf, Da: DaService, Vm: ZkvmHost>
where
    Stf: StateTransitionFunction<Vm::Guest, Da::Spec>,
{
    /// The simulator runs the rollup verifier logic without even emulating the zkVM
    Simulate(StateTransitionVerifier<Stf, Da::Verifier, Vm::Guest>),
    /// The executor runs the rollup verification logic in the zkVM, but does not actually
    /// produce a zk proof
    Execute,
    /// The prover runs the rollup verification logic in the zkVM and produces a zk proof
    Prover,
}

/// A prover for the demo rollup. Consists of a VM and a config
pub struct Prover<Stf, Da: DaService, Vm: ZkvmHost>
where
    Stf: StateTransitionFunction<Vm::Guest, Da::Spec>,
{
    /// The Zkvm Host to use
    pub vm: Vm,
    /// The prover configuration
    pub config: ProofGenConfig<Stf, Da, Vm>,
}

impl<Stf, Sm, Da, Vm, V, Root, Witness> StateTransitionRunner<Stf, Sm, Da, Vm, V>
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
    V: StateTransitionFunction<Vm::Guest, Da::Spec, StateRoot = Root, Witness = Witness>,
    V::PreState: Clone,
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
        prover: Option<Prover<V, Da, Vm>>,
        zk_storage: V::PreState,
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

        let soft_confirmation_client = SoftConfirmationClient::new(
            start_height,
            RpcConfig {
                bind_host: "0.0.0.0".to_owned(),
                bind_port: 12345,
            },
        );

        Ok(Self {
            start_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: prev_state_root,
            listen_address,
            prover,
            zk_storage,
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
        let pre_state = self.storage_manager.get_native_storage();
        let filtered_block: <Da as DaService>::FilteredBlock =
            self.da_service.get_finalized_at(self.start_height).await?;
        let blobz = self.da_service.convert_to_transaction(blob).unwrap();

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

        let mut data_to_commit = SlotCommit::new(filtered_block.clone());
        for receipt in slot_result.batch_receipts {
            data_to_commit.add_batch(receipt);
        }
        let next_state_root = slot_result.state_root;
        self.ledger_db.commit_slot(data_to_commit)?;
        self.state_root = next_state_root;
        Ok(())
    }

    /// Runs the rollup.
    pub async fn run_in_process(&mut self) -> Result<(), anyhow::Error> {
        let client = &self.soft_confirmation_client;

        let mut height = 1;
        loop {
            if let Ok(tx) = client.get_txs_range(height).await {
                info!("height: {}", height);
            } else {
                info!("height: {} not found", height);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }

            let tx = client.get_txs_range(height).await;

            if tx.is_err() {
                info!("height: {} not found", height);
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

            let filtered_block = self.da_service.get_finalized_at(2).await?;
            // let mut blobs = self.da_service.extract_relevant_blobs(&filtered_block);

            // info!(
            //     "Extracted {} relevant blobs at height {}: {:?}",
            //     new_blobs.0.len(),
            //     height,
            //     new_blobs
            //         .0
            //         .iter()
            //         .map(|b| format!(
            //             "sequencer={} blob_hash=0x{}",
            //             b.sender(),
            //             hex::encode(b.hash())
            //         ))
            //         .collect::<Vec<_>>()
            // );

            let mut data_to_commit = SlotCommit::new(filtered_block.clone());

            let pre_state = self.storage_manager.get_native_storage();
            let slot_result = self.stf.apply_slot(
                &self.state_root,
                pre_state,
                Default::default(),
                filtered_block.header(),
                &filtered_block.validity_condition(),
                &mut vec![new_blobs.0],
            );

            for receipt in slot_result.batch_receipts {
                data_to_commit.add_batch(receipt);
            }

            let next_state_root = slot_result.state_root;

            self.ledger_db.commit_slot(data_to_commit)?;
            self.state_root = next_state_root;
            println!("\nSTATE ROOT: {:?}\n", self.state_root.as_ref());
            height += 1;
        }
    }
}
