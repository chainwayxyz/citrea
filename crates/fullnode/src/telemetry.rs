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
    pub current_l1_block: Gauge,
    pub current_l2_block: Gauge,
    pub process_soft_confirmation: Histogram,
    pub scan_l1_block: Histogram,
}

pub fn setup_telemetry() -> (Arc<Registry>, Arc<TelemetryTargets>) {
    let mut registry = <Registry>::with_prefix("sequencer");

    let current_l1_block: Gauge = Default::default();
    let current_l2_block: Gauge = Default::default();
    let process_soft_confirmation: Histogram = Histogram::new(exponential_buckets(1e-6, 2.0, 22));
    let scan_l1_block: Histogram = Histogram::new(exponential_buckets(1e-6, 2.0, 22));

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
        "scan_l1_block",
        "The duration of scanning and processing a single L1 block",
        scan_l1_block.clone(),
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
            current_l1_block,
            current_l2_block,
            process_soft_confirmation,
            scan_l1_block,
        }),
    )
}
