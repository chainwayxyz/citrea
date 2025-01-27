use citrea_common::tasks::manager::TaskManager;
use citrea_common::RunnerConfig;
use tokio::signal;
use tracing::instrument;

pub struct CitreaLightClientProver {
    _runner_config: RunnerConfig,
}

impl CitreaLightClientProver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(runner_config: RunnerConfig) -> Result<Self, anyhow::Error> {
        Ok(Self {
            _runner_config: runner_config,
        })
    }

    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(&mut self, task_manager: TaskManager<()>) -> Result<(), anyhow::Error> {
        signal::ctrl_c().await.expect("Failed to listen ctrl+c");
        task_manager.abort().await;

        Ok(())
    }
}
