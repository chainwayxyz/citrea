use std::sync::Arc;

use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;

pub struct TelemetryTargets {
    pub mempool_txs: Gauge,
    pub dry_run_execution: Histogram,
    pub block_production_execution: Histogram,
    pub send_commitment_execution: Histogram,
    pub commitment_blocks_count: Gauge,
    pub current_l1_block: Gauge,
}

pub fn setup_telemetry() -> (Arc<Registry>, Arc<TelemetryTargets>) {
    let mut registry = <Registry>::with_prefix("citrea_sequencer");

    let mempool_txs: Gauge = Default::default();
    let dry_run_execution: Histogram = Histogram::new(exponential_buckets(1e-6, 2.0, 22));
    let block_production_execution: Histogram = Histogram::new(exponential_buckets(1e-6, 2.0, 22));
    let send_commitment_execution: Histogram = Histogram::new(exponential_buckets(1e-6, 2.0, 22));
    let commitment_blocks_count: Gauge = Default::default();
    let current_l1_block: Gauge = Default::default();

    registry.register(
        "mempool_tx",
        "How many transactions are currently in the mempool",
        mempool_txs.clone(),
    );
    registry.register(
        "dry_run_tx_execution",
        "The duration of dry running transactions",
        dry_run_execution.clone(),
    );
    registry.register(
        "block_production_execution",
        "The duration of executing block transactions",
        block_production_execution.clone(),
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
    (
        Arc::new(registry),
        Arc::new(TelemetryTargets {
            mempool_txs,
            dry_run_execution,
            block_production_execution,
            send_commitment_execution,
            commitment_blocks_count,
            current_l1_block,
        }),
    )
}
