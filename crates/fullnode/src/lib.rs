use std::net::SocketAddr;

pub use runner::*;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::StfBlueprint;
use tokio::sync::oneshot;
use tracing::instrument;

mod runner;

/// Dependencies needed to run the rollup.
pub struct FullNode<S: RollupBlueprint> {
    /// The State Transition Runner.
    #[allow(clippy::type_complexity)]
    pub runner: CitreaFullnode<
        StfBlueprint<S::NativeContext, S::DaSpec, S::Vm, S::NativeRuntime>,
        S::StorageManager,
        S::DaService,
        S::Vm,
        S::NativeContext,
    >,
    /// Rpc methods for the rollup.
    pub rpc_methods: jsonrpsee::RpcModule<()>,
}

impl<S: RollupBlueprint> FullNode<S> {
    /// Runs the rollup.
    #[instrument(level = "trace", skip(self), err, ret(level = "error"))]
    pub async fn run(self) -> Result<(), anyhow::Error> {
        self.run_and_report_rpc_port(None).await
    }

    /// Only run the rpc.
    pub async fn run_rpc(self) -> Result<(), anyhow::Error> {
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
