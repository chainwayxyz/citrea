//! This module defines the metrics for Bitcoin DA.

use std::sync::LazyLock;

use metrics::{Gauge, Histogram};
use metrics_derive::Metrics;

/// This defines the struct which encapsulates all metrics used for Bitcoin DA.
///
/// It is unused because we directly use gauge and histogram macros since that is the
/// only way in which we can provide additional labels to the metric.
/// However, deriving `Metrics` here is convenient to provide descriptions for each of
/// the metrics.
#[allow(unused)]
#[derive(Metrics)]
#[metrics(scope = "bitcoin_da")]
pub struct BitcoinDaMetrics {
    /// Bitcoin DA Transaction count in queue
    #[metric(describe = "How many transactions are currently in the Bitcoin DA queue")]
    pub(crate) transaction_queue_size: Gauge,
    /// Histogram tracking the time taken to process a transaction in the queue
    #[metric(describe = "The time taken to process the Bitcoin DA queue")]
    pub(crate) transaction_queue_processing_time: Histogram,
    /// The size of the transaction in bytes, used for monitoring purposes
    #[metric(describe = "The size of the transaction in bytes, used for monitoring purposes")]
    pub(crate) transaction_size: Gauge,
}

/// Bitcoin DA metrics
pub static BITCOIN_DA_METRICS: LazyLock<BitcoinDaMetrics> = LazyLock::new(|| {
    BitcoinDaMetrics::describe();
    BitcoinDaMetrics::default()
});
