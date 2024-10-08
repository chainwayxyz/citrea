mod commitment_controller;
mod db_provider;
mod deposit_data_mempool;
mod mempool;
mod rpc;
mod sequencer;
mod utils;

use std::net::SocketAddr;

pub use node_configs::{SequencerConfig, SequencerMempoolConfig};
pub use rpc::SequencerRpcClient;
pub use sequencer::CitreaSequencer;
use sov_db::ledger_db::LedgerDB;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::StfBlueprint;
use tokio::sync::oneshot;
use tracing::{instrument, Instrument};

/// Sequencer stf runner
pub struct Sequencer<S: RollupBlueprint> {
    /// The State Transition Runner of Sequencer.
    #[allow(clippy::type_complexity)]
    pub runner: CitreaSequencer<
        S::NativeContext,
        S::DaService,
        S::StorageManager,
        S::Vm,
        StfBlueprint<S::NativeContext, S::DaSpec, S::Vm, S::NativeRuntime>,
        LedgerDB,
    >,
    /// Rpc methods for the rollup.
    pub rpc_methods: jsonrpsee::RpcModule<()>,
}

impl<S: RollupBlueprint> Sequencer<S> {
    /// Runs the sequencer.
    #[instrument(
        name = "Sequencer",
        level = "info",
        skip_all,
        err,
        ret(level = "error")
    )]
    pub async fn run(self) -> Result<(), anyhow::Error> {
        self.run_and_report_rpc_port(None).await
    }

    /// Runs the sequencer.
    pub async fn run_and_report_rpc_port(
        self,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        let mut seq = self.runner;
        seq.start_rpc_server(channel, self.rpc_methods)
            .instrument(tracing::Span::current())
            .await
            .unwrap();
        seq.run().await?;
        Ok(())
    }
}
