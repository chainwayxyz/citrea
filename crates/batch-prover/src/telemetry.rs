use std::sync::Arc;

use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;

pub struct TelemetryTargets {
    pub current_l1_block: Gauge,
    pub current_l2_block: Gauge,
    pub process_soft_confirmation: Histogram,
    pub mine_da_tx: Histogram,
}

pub fn setup_telemetry() -> (Arc<Registry>, Arc<TelemetryTargets>) {
    let mut registry = <Registry>::with_prefix("sequencer");

    let current_l1_block: Gauge = Default::default();
    let current_l2_block: Gauge = Default::default();
    let process_soft_confirmation: Histogram = Histogram::new(exponential_buckets(1e-6, 2.0, 22));
    let mine_da_tx: Histogram = Histogram::new(exponential_buckets(1e-6, 2.0, 22));

    registry.register(
        "current_l1_block",
        "The current L1 block number which is used to produce L2 blocks",
        current_l1_block.clone(),
    );

    registry.register(
        "current_l2_block",
        "The current L2 block number",
        current_l1_block.clone(),
    );

    registry.register(
        "process_soft_confirmation",
        "The duration of processing a single soft confirmation",
        process_soft_confirmation.clone(),
    );

    registry.register(
        "mine_da_tx",
        "The duration of mining a DA transaction",
        mine_da_tx.clone(),
    );

    (
        Arc::new(registry),
        Arc::new(TelemetryTargets {
            current_l1_block,
            current_l2_block,
            process_soft_confirmation,
            mine_da_tx,
        }),
    )
}
