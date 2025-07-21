use std::time::Instant;

use futures::future::BoxFuture;
use futures::FutureExt;
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::types::Request;
use jsonrpsee::MethodResponse;
use metrics::histogram;

/// Wraps an inner RPC service and records response times
#[derive(Debug, Clone)]
pub struct RpcMetrics<S> {
    inner: S,
    node_type: String,
}

impl<S> RpcMetrics<S> {
    pub fn new(inner: S, node_type: String) -> Self {
        Self { inner, node_type }
    }
}

impl<'a, S> RpcServiceT<'a> for RpcMetrics<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'a,
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let service = self.inner.clone();
        let method_name = req.method_name().to_string();
        let start = Instant::now();
        let node_type = self.node_type.clone();

        async move {
            let response = service.call(req).await;

            let elapsed = start.elapsed().as_secs_f64();
            let success = response.is_success().to_string();

            let hist_title = format!("{}_rpc_response_time", node_type);

            histogram!(
                hist_title,
                "method" => method_name,
                "success" => success,
            )
            .record(elapsed);

            response
        }
        .boxed()
    }
}
