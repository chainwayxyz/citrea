use std::sync::Arc;

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;

pub struct TelemetryTargets {
    mem_pool_tx: Gauge,
}

pub fn setup_telemetry() -> (Arc<Registry>, TelemetryTargets) {
    let mut registry = <Registry>::with_prefix("citrea_sequencer");

    let mem_pool_tx: Gauge = Default::default();
    let inbound_mem_pool_tx: Gauge = Default::default();
    let dry_run_tx_execution: Histogram = Histogram::new(exponential_buckets(1e-6, 2.0, 22));
    let block_production_tx_execution: Histogram =
        Histogram::new(exponential_buckets(1e-6, 2.0, 22));
    let send_commitment_execution: Histogram = Histogram::new(exponential_buckets(1e-6, 2.0, 22));
    let commitment_blocks_count: Histogram = Histogram::new(exponential_buckets(1e-6, 2.0, 22));
    let current_l1_block: Counter = Default::default();

    registry.register(
        "mem_pool_tx",
        "How many transactions are currently in the mempool",
        mem_pool_tx.clone(),
    );
    registry.register(
        "dry_run_tx_execution",
        "The duration of dry running transactions",
        dry_run_tx_execution.clone(),
    );
    registry.register(
        "block_production_tx_execution",
        "The duration of executing block transactions",
        block_production_tx_execution.clone(),
    );
    registry.register(
        "send_commitment_execution",
        "The duration of sending a sequencer commitment",
        send_commitment_execution.clone(),
    );
    registry.register(
        "commitment_blocks_count",
        "The number of blocks included in a sequencer commitment",
        commitment_blocks_count.clone(),
    );
    registry.register(
        "current_l1_block",
        "The current L1 block number which is used to produce L2 blocks",
        current_l1_block.clone(),
    );
    (Arc::new(registry), TelemetryTargets { mem_pool_tx })
}
