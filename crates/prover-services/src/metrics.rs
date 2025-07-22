//! Metrics collection for the parallel prover service
//!
//! This module defines metrics that track various aspects of parallel prover service,
//! including block processing times and current block numbers.
use std::sync::LazyLock;

use metrics::Gauge;
use metrics_derive::Metrics;

/// Collection of metrics for monitoring parallel prover service performance and state
#[derive(Metrics)]
#[metrics(scope = "parallel_prover_service")]
pub struct ParallelProverMetrics {
    /// Number of ongoing proving jobs
    #[metric(describe = "Number of ongoing proving jobs")]
    pub ongoing_proving_jobs: Gauge,

    /// Number of proofs waiting in queue to be processed because of PARALLEL_PROOF_LIMIT
    #[metric(describe = "Number of proofs waiting in queue to be processed")]
    pub proof_count_waiting_in_queue: Gauge,
}

/// Parallel prover metrics
pub static PARALLEL_PROVER_METRICS: LazyLock<ParallelProverMetrics> = LazyLock::new(|| {
    ParallelProverMetrics::describe();
    ParallelProverMetrics::default()
});
