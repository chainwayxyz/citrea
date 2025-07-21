// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use std::sync::LazyLock;

use metrics::{Counter, Histogram};
use metrics_derive::Metrics;

/// This defines the struct which encapsulates all metrics used for schema DB.
///
/// It is unused because we directly use gauge and histogram macros since that is the
/// only way in which we can provide additional labels to the metric.
/// However, deriving `Metrics` here is convenient to provide descriptions for each of
/// the metrics.
#[allow(unused)]
#[derive(Metrics)]
#[metrics(scope = "schemadb")]
pub struct SchemaDbMetrics {
    #[metric(describe = "Storage delete calls")]
    pub(crate) deletes: Counter,
    #[metric(describe = "Schemadb iter latency in seconds")]
    pub(crate) iter_latency_seconds: Histogram,
    #[metric(describe = "Schemadb iter size in bytes")]
    pub(crate) iter_bytes: Histogram,
    #[metric(describe = "Schemadb get latency in seconds")]
    pub(crate) get_latency_seconds: Histogram,
    #[metric(describe = "Schemadb get call returned data size in bytes")]
    pub(crate) get_bytes: Histogram,
    #[metric(describe = "Schemadb schema batch commit latency in seconds")]
    pub(crate) batch_commit_latency_seconds: Histogram,
    #[metric(describe = "Schemadb schema batch commit size in bytes")]
    pub(crate) batch_commit_bytes: Histogram,
    #[metric(describe = "sov_schema_db put call puts data size in bytes")]
    pub(crate) batch_put_bytes: Histogram,
    #[metric(describe = "sov_schema_db schema batch put latency in seconds")]
    pub(crate) batch_put_latency_seconds: Histogram,
    #[metric(describe = "Schemadb cache hits")]
    pub(crate) cache_hits: Counter,
    #[metric(describe = "Schemadb cache misses")]
    pub(crate) cache_misses: Counter,
}

/// Schema DB metrics
pub static SCHEMADB_METRICS: LazyLock<SchemaDbMetrics> = LazyLock::new(|| {
    SchemaDbMetrics::describe();
    SchemaDbMetrics::default()
});
