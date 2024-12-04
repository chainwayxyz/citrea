use std::net::SocketAddr;

use sov_db::ledger_db::LedgerDB;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::StfBlueprint;
use tokio::sync::oneshot;
use tracing::instrument;

mod da_block_handler;
pub mod db_migrations;
mod errors;
mod runner;
pub use runner::*;
mod proving;
pub mod rpc;

pub use proving::GroupCommitments;

/// Dependencies needed to run the rollup.
pub struct BatchProver<S: RollupBlueprint> {
    /// The State Transition Runner.
    #[allow(clippy::type_complexity)]
    pub runner: CitreaBatchProver<
        S::NativeContext,
        S::DaService,
        S::StorageManager,
        S::Vm,
        StfBlueprint<S::NativeContext, S::DaSpec, S::NativeRuntime>,
        S::ProverService,
        LedgerDB,
    >,
    /// Rpc methods for the rollup.
    pub rpc_methods: jsonrpsee::RpcModule<()>,
}

impl<S: RollupBlueprint> BatchProver<S> {
    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err, ret(level = "error"))]
    pub async fn run(self) -> Result<(), anyhow::Error> {
        self.run_and_report_rpc_port(None).await
    }

    /// Only run the rpc.
    pub async fn run_rpc(mut self) -> Result<(), anyhow::Error> {
        self.runner.start_rpc_server(self.rpc_methods, None).await?;
        Ok(())
    }

    /// Runs the rollup. Reports rpc port to the caller using the provided channel.
    pub async fn run_and_report_rpc_port(
        self,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        let mut runner = self.runner;
        runner.start_rpc_server(self.rpc_methods, channel).await?;

        runner.run().await?;
        Ok(())
    }
}
