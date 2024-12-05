// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use once_cell::sync::Lazy;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};

pub struct CounterTarget<'a> {
    pub name: &'static str,
    pub help: &'static str,
    pub counter: Family<(&'static str, &'a str), Counter>,
}
pub struct HistogramTarget<'a> {
    pub name: &'static str,
    pub help: &'static str,
    pub histogram: Family<(&'static str, &'a str), Histogram>,
}

pub static SCHEMADB_ITER_LATENCY_SECONDS: Lazy<HistogramTarget> = Lazy::new(|| {
    HistogramTarget {
        // metric name
        name: "schemadb_iter_latency_seconds",
        // metric description
        help: "Schemadb iter latency in seconds",
        histogram: Family::<(&'static str, &str), Histogram>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(
                /*start=*/ 1e-6, /*factor=*/ 2.0, /*count=*/ 22,
            ))
        }),
    }
});

pub static SCHEMADB_ITER_BYTES: Lazy<HistogramTarget> = Lazy::new(|| {
    HistogramTarget {
        // metric name
        name: "schemadb_iter_bytes",
        // metric description
        help: "Schemadb iter size in bytes",
        histogram: Family::<(&'static str, &str), Histogram>::new_with_constructor(|| {
            Histogram::new([].into_iter())
        }),
    }
});

pub static SCHEMADB_GET_LATENCY_SECONDS: Lazy<HistogramTarget> = Lazy::new(|| {
    HistogramTarget {
        // metric name
        name: "schemadb_get_latency_seconds",
        // metric description
        help: "Schemadb get latency in seconds",
        histogram: Family::<(&'static str, &str), Histogram>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(
                /*start=*/ 1e-6, /*factor=*/ 2.0, /*count=*/ 22,
            ))
        }),
    }
});

pub static SCHEMADB_GET_BYTES: Lazy<HistogramTarget> = Lazy::new(|| {
    HistogramTarget {
        // metric name
        name: "schemadb_get_bytes",
        // metric description
        help: "Schemadb get call returned data size in bytes",
        histogram: Family::<(&'static str, &str), Histogram>::new_with_constructor(|| {
            Histogram::new([].into_iter())
        }),
    }
});

pub static SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS: Lazy<HistogramTarget> = Lazy::new(|| {
    HistogramTarget {
        // metric name
        name: "schemadb_batch_commit_latency_seconds",
        // metric description
        help: "Schemadb schema batch commit latency in seconds",
        histogram: Family::<(&'static str, &str), Histogram>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(
                /*start=*/ 1e-3, /*factor=*/ 2.0, /*count=*/ 20,
            ))
        }),
    }
});

pub static SCHEMADB_BATCH_COMMIT_BYTES: Lazy<HistogramTarget> = Lazy::new(|| {
    HistogramTarget {
        // metric name
        name: "schemadb_batch_commit_bytes",
        // metric description
        help: "Schemadb schema batch commit size in bytes",
        histogram: Family::<(&'static str, &str), Histogram>::new_with_constructor(|| {
            Histogram::new([].into_iter())
        }),
    }
});

pub static SCHEMADB_PUT_BYTES: Lazy<HistogramTarget> = Lazy::new(|| {
    HistogramTarget {
        // metric name
        name: "sov_schema_db_put_bytes",
        // metric description
        help: "sov_schema_db put call puts data size in bytes",
        histogram: Family::<(&'static str, &str), Histogram>::new_with_constructor(|| {
            Histogram::new([].into_iter())
        }),
    }
});

pub static SCHEMADB_DELETES: Lazy<CounterTarget> = Lazy::new(|| CounterTarget {
    name: "storage_deletes",
    help: "Storage delete calls",
    counter: Default::default(),
});

pub static SCHEMADB_BATCH_PUT_LATENCY_SECONDS: Lazy<HistogramTarget> = Lazy::new(|| {
    HistogramTarget {
        // metric name
        name: "sov_schema_db_batch_put_latency_seconds",
        // metric description
        help: "sov_schema_db schema batch put latency in seconds",
        // metric labels (dimensions)
        histogram: Family::<(&'static str, &str), Histogram>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(
                /*start=*/ 1e-3, /*factor=*/ 2.0, /*count=*/ 20,
            ))
        }),
    }
});
