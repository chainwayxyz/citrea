use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures::Future;
use http_body_util::{combinators, BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use tokio::net::TcpListener;
use tokio::pin;
use tokio_util::sync::CancellationToken;

/// Boxed HTTP body for responses
type BoxBody = combinators::BoxBody<Bytes, hyper::Error>;

pub async fn start_telemetry_server(
    addr: SocketAddr,
    registry: Registry,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let registry = Arc::new(registry);
    let tcp_listener = TcpListener::bind(addr).await.unwrap();
    let server = hyper::server::conn::http1::Builder::new();
    while let Ok((stream, _)) = tcp_listener.accept().await {
        let io = TokioIo::new(stream);

        let server_clone = server.clone();
        let registry_clone = registry.clone();
        let cancellation_signal = cancellation_token.clone();
        tokio::task::spawn(async move {
            let conn = server_clone.serve_connection(io, service_fn(make_handler(registry_clone)));
            pin!(conn);
            tokio::select! {
                _ = conn.as_mut() => {}
                _ = cancellation_signal.cancelled() => {
                    conn.as_mut().graceful_shutdown();
                }
            }
        });
    }
    Ok(())
}

/// This function returns a HTTP handler (i.e. another function)
pub fn make_handler(
    registry: Arc<Registry>,
) -> impl Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = std::io::Result<Response<BoxBody>>> + Send>>
{
    // This closure accepts a request and responds with the OpenMetrics encoding of our metrics.
    move |_req: Request<Incoming>| {
        let reg = registry.clone();

        Box::pin(async move {
            let mut buf = String::new();
            encode(&mut buf, &reg.clone())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                .map(|_| {
                    let body = full(Bytes::from(buf));
                    Response::builder()
                        .header(
                            hyper::header::CONTENT_TYPE,
                            "application/openmetrics-text; version=1.0.0; charset=utf-8",
                        )
                        .body(body)
                        .unwrap()
                })
        })
    }
}

/// helper function to build a full boxed body
pub fn full(body: Bytes) -> BoxBody {
    Full::new(body).map_err(|never| match never {}).boxed()
}
