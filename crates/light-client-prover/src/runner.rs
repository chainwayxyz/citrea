use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use citrea_common::tasks::manager::TaskManager;
use jsonrpsee::server::{BatchRequestConfig, ServerBuilder};
use jsonrpsee::RpcModule;
use sov_db::ledger_db::{LedgerDB, LightClientProverLedgerOps};
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::{
    LightClientProverConfig, ProverService, RollupPublicKeys, RpcConfig, RunnerConfig,
};
use tokio::sync::oneshot;
use tracing::{error, info, instrument};

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
    Da: DaService,
    Vm: ZkvmHost,
    Ps: ProverService<Vm>,
    DB: LightClientProverLedgerOps,
{
    runner_config: RunnerConfig,
    public_keys: RollupPublicKeys,
    rpc_config: RpcConfig,
    da_service: Arc<Da>,
    ledger_db: DB,
    prover_service: Arc<Ps>,
    prover_config: LightClientProverConfig,
    task_manager: TaskManager<()>,
    batch_proof_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
}

impl<Da, Vm, Ps, DB> CitreaLightClientProver<Da, Vm, Ps, DB>
where
    Da: DaService,
    Vm: ZkvmHost,
    Ps: ProverService<Vm>,
    DB: LightClientProverLedgerOps,
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
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            runner_config,
            public_keys,
            rpc_config,
            da_service,
            ledger_db,
            prover_service,
            prover_config,
            task_manager: TaskManager::default(),
            batch_proof_commitments_by_spec,
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
        todo!()
    }
}
