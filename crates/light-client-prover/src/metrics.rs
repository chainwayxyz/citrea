use metrics::Gauge;
use metrics_derive::Metrics;
use once_cell::sync::Lazy;

#[derive(Metrics)]
#[metrics(scope = "light_client_prover")]
pub struct LightClientProverMetrics {
    #[metric(describe = "The current L1 block number which is used to produce L2 blocks")]
    pub current_l1_block: Gauge,
}

/// Light client metrics
pub static LIGHT_CLIENT_METRICS: Lazy<LightClientProverMetrics> = Lazy::new(|| {
    LightClientProverMetrics::describe();
    LightClientProverMetrics::default()
});
