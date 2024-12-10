//! Provide the data structure for telemetry targets
//! for DA services.
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};

/// DA telemetry targets
#[derive(Clone, Debug)]
pub struct DaTelemetryTargets {
    /// Duration to mine DA transaction.
    pub mine_da_tx: Histogram,
}

impl Default for DaTelemetryTargets {
    fn default() -> Self {
        DaTelemetryTargets {
            mine_da_tx: Histogram::new(exponential_buckets(1e-6, 2.0, 22)),
        }
    }
}

/// DA telemetry targets
#[derive(Clone, Debug)]
pub struct ProvingSessionTelemetryTargets {
    /// Proving session cycles count
    pub cycle_count: Histogram,
}

impl Default for ProvingSessionTelemetryTargets {
    fn default() -> Self {
        ProvingSessionTelemetryTargets {
            cycle_count: Histogram::new(exponential_buckets(1e-6, 2.0, 22)),
        }
    }
}
