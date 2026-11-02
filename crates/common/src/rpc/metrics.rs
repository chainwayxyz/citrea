use std::time::Instant;

use futures::future::BoxFuture;
use futures::FutureExt;
use jsonrpsee::core::server::Methods;
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::types::Request;
use jsonrpsee::MethodResponse;
use metrics::{counter, histogram};

/// Wraps an inner RPC service and records response times
#[derive(Debug, Clone)]
pub struct RpcMetrics<S> {
    service: S,
    methods: Methods,
}

impl<S> RpcMetrics<S> {
    pub fn new(service: S, methods: Methods) -> Self {
        Self { service, methods }
    }
}

impl<'a, S> RpcServiceT<'a> for RpcMetrics<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'a,
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let service = self.service.clone();
        // Only registered names may become labels, keeping client input from growing metrics.
        let method_name = self
            .methods
            .method_with_name(req.method_name())
            .map_or("unknown", |(name, _)| name);
        let start = Instant::now();

        async move {
            let response = service.call(req).await;

            let elapsed = start.elapsed().as_secs_f64();
            let success = response.is_success().to_string();

            counter!(
                "rpc_requests_total",
                "method" => method_name,
                "success" => success.clone(),
            )
            .increment(1);
            histogram!(
                "rpc_response_time_seconds",
                "method" => method_name,
                "success" => success,
            )
            .record(elapsed);

            response
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use jsonrpsee::core::client::{ClientT, Error};
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::server::{RpcServiceBuilder, ServerBuilder};
    use jsonrpsee::types::error::{ErrorCode, ErrorObjectOwned};
    use jsonrpsee::{rpc_params, RpcModule};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    use super::*;

    #[test]
    fn method_labels_are_bounded_by_registered_methods() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        // Keep the server and its recorder on the same thread.
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let mut methods = RpcModule::new(());
                    methods
                        .register_method("test_success", |_, _, _| true)
                        .unwrap();
                    methods
                        .register_alias("test_alias", "test_success")
                        .unwrap();
                    methods
                        .register_method("test_failure", |_, _, _| {
                            Err::<(), _>(ErrorObjectOwned::from(ErrorCode::MethodNotFound))
                        })
                        .unwrap();

                    let registered_methods: Methods = methods.clone().into();
                    let server = ServerBuilder::default()
                        .set_rpc_middleware(RpcServiceBuilder::new().layer_fn(move |service| {
                            RpcMetrics::new(service, registered_methods.clone())
                        }))
                        .build("127.0.0.1:0")
                        .await
                        .unwrap();
                    let address = server.local_addr().unwrap();
                    let handle = server.start(methods);
                    let client = HttpClientBuilder::default()
                        .build(format!("http://{address}"))
                        .unwrap();

                    for name in ["test_success", "test_alias"] {
                        assert!(client
                            .request::<bool, _>(name, rpc_params![])
                            .await
                            .unwrap());
                    }

                    let unknown_names: Vec<_> = (0..100)
                        .map(|i| format!("unknown_{i}"))
                        .chain([
                            String::new(),
                            "x".repeat(65_536),
                            "test_success_未知".into(),
                        ])
                        .collect();
                    for name in unknown_names
                        .iter()
                        .map(String::as_str)
                        .chain(["test_failure"])
                    {
                        let error = client
                            .request::<bool, _>(name, rpc_params![])
                            .await
                            .unwrap_err();
                        assert!(matches!(error, Error::Call(error) if error.code() == -32601));
                    }

                    handle.stop().unwrap();
                    handle.stopped().await;
                });
        });

        let snapshot = snapshotter.snapshot().into_vec();
        // A counter and a histogram for each registered method and the unknown bucket.
        assert_eq!(snapshot.len(), 8);
        for (key, _, _, value) in snapshot {
            let labels: Vec<_> = key.key().labels().map(|l| (l.key(), l.value())).collect();
            let count = match labels.as_slice() {
                [("method", "unknown"), ("success", "false")] => 103,
                [("method", "test_success" | "test_alias"), ("success", "true")]
                | [("method", "test_failure"), ("success", "false")] => 1,
                _ => panic!("unexpected metric labels: {labels:?}"),
            };
            match (key.key().name(), value) {
                ("rpc_requests_total", DebugValue::Counter(value)) => assert_eq!(value, count),
                ("rpc_response_time_seconds", DebugValue::Histogram(values)) => {
                    assert_eq!(values.len() as u64, count);
                }
                (name, value) => panic!("unexpected metric: {name} {value:?}"),
            }
        }
    }
}
