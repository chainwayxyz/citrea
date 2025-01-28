use citrea_common::RunnerConfig;
use tokio_util::sync::CancellationToken;
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
    pub async fn run(
        &mut self,
        cancellation_token: CancellationToken,
    ) -> Result<(), anyhow::Error> {
        cancellation_token.cancelled().await;

        Ok(())
    }
}
