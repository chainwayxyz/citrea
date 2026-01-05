//! Metrics collection for the light client prover
//!
//! This module defines metrics that track aspects of light client prover operation,
//! including L1 block processing times and current L1 block number.
use std::sync::LazyLock;

use metrics::Gauge;
use metrics_derive::Metrics;

#[derive(Metrics)]
#[metrics(scope = "light_client_prover")]
/// Collection of metrics for monitoring light client performance and state
pub struct LightClientProverMetrics {
    #[metric(describe = "The height of the last L1 block proved")]
    /// The height of the last L1 block proved
    pub current_l1_block: Gauge,
    /// The duration of scanning and processing a single L1 block
    #[metric(describe = "The duration of scanning and processing a single L1 block")]
    pub scan_l1_block_duration_secs: Gauge,
    /// Tracking the time taken to prove a state transition, gauge because one proof is generated per l1 block
    #[metric(describe = "The duration of generating a light client proof")]
    pub proving_time: Gauge,
    /// Gauge for the highest proven commitment index
    #[metric(describe = "The highest proven commitment index")]
    pub highest_proven_index: Gauge,
    /// Gauge for the highest proven l2 height
    #[metric(describe = "The highest proven l2 height")]
    pub highest_proven_l2_height: Gauge,
}

impl LightClientProverMetrics {
    /// Record for both gauge and histogram
    /// Gauge is used for per block exact time tracking, histogram is used for average and quantiles
    pub fn set_scan_l1_block_duration(&self, duration: f64) {
        self.scan_l1_block_duration_secs.set(duration);
        // also set histogram so we can follow average and quantiles properly
        metrics::histogram!("light_client_prover_scan_l1_block_duration_secs").record(duration);
    }

    /// Record for both gauge and histogram
    /// Gauge is used for per block exact time tracking, histogram is used for average and quantiles
    pub(crate) fn set_lcp_proving_time(&self, duration: f64) {
        self.proving_time.set(duration);
        // also set histogram so we can follow average and quantiles properly
        metrics::histogram!("light_client_prover_proving_time_histogram").record(duration);
    }
}

/// Light client metrics
pub static LIGHT_CLIENT_METRICS: LazyLock<LightClientProverMetrics> = LazyLock::new(|| {
    LightClientProverMetrics::describe();
    LightClientProverMetrics::default()
});

/// Initializes light client prover metrics with current DB state
///
/// # Arguments
/// * `ledger_db` - The ledgerDB to read metrics from
///
/// # Errors
/// Returns error if database operations fail
pub fn initialize_metrics<DB>(ledger_db: &DB) -> Result<(), anyhow::Error>
where
    DB: sov_db::ledger_db::LightClientProverLedgerOps,
{
    use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
    use tracing::debug;

    if let Ok(Some(last_scanned_l1_height)) = ledger_db.get_last_scanned_l1_height() {
        let l1_height = last_scanned_l1_height.0;

        if let Ok(Some(proof_data)) = ledger_db.get_light_client_proof_data_by_l1_height(l1_height)
        {
            let circuit_output =
                LightClientCircuitOutput::from(proof_data.light_client_proof_output);

            LIGHT_CLIENT_METRICS.current_l1_block.set(l1_height as f64);
            LIGHT_CLIENT_METRICS
                .highest_proven_l2_height
                .set(circuit_output.last_l2_height as f64);
            LIGHT_CLIENT_METRICS
                .highest_proven_index
                .set(circuit_output.last_sequencer_commitment_index as f64);

            debug!(
                "Initialized metrics from L1 block {}: L2 height {} at index {}",
                l1_height,
                circuit_output.last_l2_height,
                circuit_output.last_sequencer_commitment_index
            );
        }
    }

    Ok(())
}
