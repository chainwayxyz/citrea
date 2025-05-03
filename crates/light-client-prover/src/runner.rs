use citrea_common::RunnerConfig;
use reth_tasks::shutdown::GracefulShutdown;
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
    #[instrument(name = "LightClientProver", skip_all)]
    pub async fn run(&mut self, shutdown_signal: GracefulShutdown) -> Result<(), anyhow::Error> {
        let _ = shutdown_signal.await;

        Ok(())
    }
}
