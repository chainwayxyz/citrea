use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

pub struct TelemetryTargets {
    mem_pool_tx: Gauge,
}

pub fn setup_telemetry() -> (Registry, TelemetryTargets) {
    let mut registry = <Registry>::with_prefix("sequencer");

    let mem_pool_tx: Gauge = Default::default();

    registry.register(
        "mem_pool_tx",
        "How many transactions are currently in the mempool",
        mem_pool_tx.clone(),
    );

    (registry, TelemetryTargets { mem_pool_tx })
}
