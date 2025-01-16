use citrea_common::tasks::manager::TaskManager;
use citrea_common::RunnerConfig;
use sov_db::ledger_db::{LightClientProverLedgerOps, SharedLedgerOps};
use tokio::signal;
use tracing::instrument;

use crate::rpc::{create_rpc_module, RpcContext};

pub enum StartVariant {
    LastScanned(u64),
    FromBlock(u64),
}

pub struct CitreaLightClientProver<DB>
where
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone,
{
    _runner_config: RunnerConfig,
    ledger_db: DB,
    task_manager: TaskManager<()>,
}

impl<DB> CitreaLightClientProver<DB>
where
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner_config: RunnerConfig,
        ledger_db: DB,
        task_manager: TaskManager<()>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            _runner_config: runner_config,
            ledger_db,
            task_manager,
        })
    }

    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        signal::ctrl_c().await.expect("Failed to listen ctrl+c");
        self.task_manager.abort().await;

        Ok(())
    }

    /// Creates a shared RpcContext with all required data.
    fn create_rpc_context(&self) -> RpcContext<DB> {
        RpcContext {
            ledger: self.ledger_db.clone(),
        }
    }

    /// Updates the given RpcModule with Prover methods.
    pub fn register_rpc_methods(
        &self,
        mut rpc_methods: jsonrpsee::RpcModule<()>,
    ) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
        let rpc_context = self.create_rpc_context();
        let rpc = create_rpc_module(rpc_context);
        rpc_methods.merge(rpc)?;
        Ok(rpc_methods)
    }
}
