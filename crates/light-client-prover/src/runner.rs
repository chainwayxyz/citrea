use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use citrea_common::tasks::manager::TaskManager;
use citrea_common::{LightClientProverConfig, RollupPublicKeys, RpcConfig, RunnerConfig};
use jsonrpsee::server::{BatchRequestConfig, ServerBuilder};
use jsonrpsee::RpcModule;
use sov_db::ledger_db::{LedgerDB, LightClientProverLedgerOps, SharedLedgerOps};
use sov_db::schema::types::SlotNumber;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::ProverService;
use tokio::signal;
use tokio::sync::oneshot;
use tracing::{error, info, instrument};

use crate::da_block_handler::L1BlockHandler;

/// Dependencies needed to run the rollup.
pub struct LightClientProver<S: RollupBlueprint> {
    /// The State Transition Runner.
    #[allow(clippy::type_complexity)]
    pub runner: CitreaLightClientProver<S::DaService, S::Vm, S::ProverService, LedgerDB>,
    /// Rpc methods for the rollup.
    pub rpc_methods: jsonrpsee::RpcModule<()>,
}

impl<S: RollupBlueprint> LightClientProver<S> {
    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err, ret(level = "error"))]
    pub async fn run(self) -> Result<(), anyhow::Error> {
        self.run_and_report_rpc_port(None).await
    }

    /// Only run the rpc.
    pub async fn run_rpc(mut self) -> Result<(), anyhow::Error> {
        self.runner.start_rpc_server(self.rpc_methods, None).await;
        Ok(())
    }

    /// Runs the rollup. Reports rpc port to the caller using the provided channel.
    pub async fn run_and_report_rpc_port(
        self,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        let mut runner = self.runner;
        runner.start_rpc_server(self.rpc_methods, channel).await;

        runner.run().await?;
        Ok(())
    }
}

pub struct CitreaLightClientProver<Da, Vm, Ps, DB>
where
    Da: DaService + Send + Sync,
    Vm: ZkvmHost,
    Ps: ProverService<Vm>,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone,
{
    _runner_config: RunnerConfig,
    public_keys: RollupPublicKeys,
    rpc_config: RpcConfig,
    da_service: Arc<Da>,
    ledger_db: DB,
    prover_service: Arc<Ps>,
    prover_config: LightClientProverConfig,
    task_manager: TaskManager<()>,
    batch_proof_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    light_client_proof_commitment: Vm::CodeCommitment,
}

impl<Da, Vm, Ps, DB> CitreaLightClientProver<Da, Vm, Ps, DB>
where
    Da: DaService<Error = anyhow::Error> + Send + Sync + 'static,
    Vm: ZkvmHost,
    Ps: ProverService<Vm, DaService = Da> + Send + Sync + 'static,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner_config: RunnerConfig,
        public_keys: RollupPublicKeys,
        rpc_config: RpcConfig,
        da_service: Arc<Da>,
        ledger_db: DB,
        prover_service: Arc<Ps>,
        prover_config: LightClientProverConfig,
        batch_proof_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
        light_client_proof_commitment: Vm::CodeCommitment,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            _runner_config: runner_config,
            public_keys,
            rpc_config,
            da_service,
            ledger_db,
            prover_service,
            prover_config,
            task_manager: TaskManager::default(),
            batch_proof_commitments_by_spec,
            light_client_proof_commitment,
        })
    }

    /// Starts a RPC server with provided rpc methods.
    pub async fn start_rpc_server(
        &mut self,
        methods: RpcModule<()>,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) {
        let bind_host = match self.rpc_config.bind_host.parse() {
            Ok(bind_host) => bind_host,
            Err(e) => {
                error!("Failed to parse bind host: {}", e);
                return;
            }
        };
        let listen_address = SocketAddr::new(bind_host, self.rpc_config.bind_port);

        let max_connections = self.rpc_config.max_connections;
        let max_subscriptions_per_connection = self.rpc_config.max_subscriptions_per_connection;
        let max_request_body_size = self.rpc_config.max_request_body_size;
        let max_response_body_size = self.rpc_config.max_response_body_size;
        let batch_requests_limit = self.rpc_config.batch_requests_limit;

        let middleware = tower::ServiceBuilder::new().layer(citrea_common::rpc::get_cors_layer());
        //  .layer(citrea_common::rpc::get_healthcheck_proxy_layer());

        self.task_manager.spawn(|cancellation_token| async move {
            let server = ServerBuilder::default()
                .max_connections(max_connections)
                .max_subscriptions_per_connection(max_subscriptions_per_connection)
                .max_request_body_size(max_request_body_size)
                .max_response_body_size(max_response_body_size)
                .set_batch_request_config(BatchRequestConfig::Limit(batch_requests_limit))
                .set_http_middleware(middleware)
                .build([listen_address].as_ref())
                .await;

            match server {
                Ok(server) => {
                    let bound_address = match server.local_addr() {
                        Ok(address) => address,
                        Err(e) => {
                            error!("{}", e);
                            return;
                        }
                    };
                    if let Some(channel) = channel {
                        if let Err(e) = channel.send(bound_address) {
                            error!("Could not send bound_address {}: {}", bound_address, e);
                            return;
                        }
                    }
                    info!("Starting RPC server at {} ", &bound_address);

                    let _server_handle = server.start(methods);
                    cancellation_token.cancelled().await;
                }
                Err(e) => {
                    error!("Could not start RPC server: {}", e);
                }
            }
        });
    }

    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        let last_l1_height_scanned = self
            .ledger_db
            .get_last_scanned_l1_height()?
            .unwrap_or(SlotNumber(1));

        let prover_config = self.prover_config.clone();
        let prover_service = self.prover_service.clone();
        let ledger_db = self.ledger_db.clone();
        let da_service = self.da_service.clone();
        let batch_prover_da_pub_key = self.public_keys.prover_da_pub_key.clone();
        let batch_proof_commitments_by_spec = self.batch_proof_commitments_by_spec.clone();
        let light_client_proof_commitment = self.light_client_proof_commitment.clone();

        self.task_manager.spawn(|cancellation_token| async move {
            let l1_block_handler = L1BlockHandler::<Vm, Da, Ps, DB>::new(
                prover_config,
                prover_service,
                ledger_db,
                da_service,
                batch_prover_da_pub_key,
                batch_proof_commitments_by_spec,
                light_client_proof_commitment,
            );
            l1_block_handler
                .run(last_l1_height_scanned.0, cancellation_token)
                .await
        });

        // Temporary fix
        signal::ctrl_c().await.expect("Failed to listen ctrl+c");
        Ok(())

        // TODO: update this once l2 sync is implemented
        // loop {
        //     select! {
        //         _ = signal::ctrl_c() => {
        //             info!("Shutting down");
        //             self.task_manager.abort().await;
        //             return Ok(());
        //         }
        //     }
        // }
    }
}
