use std::time::Instant;

use futures::future::BoxFuture;
use futures::FutureExt;
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::types::Request;
use jsonrpsee::MethodResponse;
use metrics::{counter, histogram};

/// Wraps an inner RPC service and records response times
#[derive(Debug, Clone)]
pub struct RpcMetrics<S>(pub S);

impl<'a, S> RpcServiceT<'a> for RpcMetrics<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'a,
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let service = self.0.clone();
        let method_name = req.method_name().to_string();
        let start = Instant::now();

        async move {
            let response = service.call(req).await;

            let elapsed = start.elapsed().as_secs_f64();
            let success = response.is_success().to_string();

            counter!(
                "rpc_requests_total",
                "method" => method_name.clone(),
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
