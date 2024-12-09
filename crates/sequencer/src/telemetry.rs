use std::sync::Arc;

use citrea_common::TelemetryConfig;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use sov_schema_db::telemetry::{
    SCHEMADB_BATCH_COMMIT_BYTES, SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS,
    SCHEMADB_BATCH_PUT_LATENCY_SECONDS, SCHEMADB_DELETES, SCHEMADB_GET_BYTES,
    SCHEMADB_GET_LATENCY_SECONDS, SCHEMADB_ITER_BYTES, SCHEMADB_ITER_LATENCY_SECONDS,
    SCHEMADB_PUT_BYTES,
};

pub struct Telemetry {
    pub(crate) config: TelemetryConfig,
    pub(crate) registry: Arc<Registry>,
    pub(crate) targets: Arc<TelemetryTargets>,
}

impl Telemetry {
    pub fn new(
        config: TelemetryConfig,
        registry: Arc<Registry>,
        targets: Arc<TelemetryTargets>,
    ) -> Self {
        Self {
            config,
            registry,
            targets,
        }
    }
}

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

    registry.register(
        SCHEMADB_ITER_LATENCY_SECONDS.name,
        SCHEMADB_ITER_LATENCY_SECONDS.help,
        SCHEMADB_ITER_LATENCY_SECONDS.histogram.clone(),
    );
    registry.register(
        SCHEMADB_ITER_BYTES.name,
        SCHEMADB_ITER_BYTES.help,
        SCHEMADB_ITER_BYTES.histogram.clone(),
    );

    registry.register(
        SCHEMADB_GET_LATENCY_SECONDS.name,
        SCHEMADB_GET_LATENCY_SECONDS.help,
        SCHEMADB_GET_LATENCY_SECONDS.histogram.clone(),
    );

    registry.register(
        SCHEMADB_GET_BYTES.name,
        SCHEMADB_GET_BYTES.help,
        SCHEMADB_GET_BYTES.histogram.clone(),
    );

    registry.register(
        SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS.name,
        SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS.help,
        SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS.histogram.clone(),
    );

    registry.register(
        SCHEMADB_BATCH_COMMIT_BYTES.name,
        SCHEMADB_BATCH_COMMIT_BYTES.help,
        SCHEMADB_BATCH_COMMIT_BYTES.histogram.clone(),
    );

    registry.register(
        SCHEMADB_PUT_BYTES.name,
        SCHEMADB_PUT_BYTES.help,
        SCHEMADB_PUT_BYTES.histogram.clone(),
    );

    registry.register(
        SCHEMADB_BATCH_PUT_LATENCY_SECONDS.name,
        SCHEMADB_BATCH_PUT_LATENCY_SECONDS.help,
        SCHEMADB_BATCH_PUT_LATENCY_SECONDS.histogram.clone(),
    );

    registry.register(
        SCHEMADB_DELETES.name,
        SCHEMADB_DELETES.help,
        SCHEMADB_DELETES.counter.clone(),
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
