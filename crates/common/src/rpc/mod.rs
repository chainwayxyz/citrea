//! Common RPC crate provides helper methods that are needed in rpc servers
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoff;
use futures::future::{BoxFuture, Either};
use futures::FutureExt;
use hyper::header::{HeaderMap, HeaderName};
use hyper::Method;
use jsonrpsee::core::RegisterMethodError;
use jsonrpsee::http_client::transport::HttpBackend;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder, HttpRequest};
use jsonrpsee::server::middleware::http::ProxyGetRequestLayer;
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::{ErrorObjectOwned, Request};
use jsonrpsee::{MethodResponse, RpcModule};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::schema::types::L2BlockNumber;
use sov_rollup_interface::services::da::DaService;
use tokio::task::futures::TaskLocalFuture;
use tower::util::MapRequest;
use tower_http::cors::{Any, CorsLayer};

mod auth;
pub mod eip_7966;
mod metrics;
pub(crate) use metrics::RpcMetrics;
pub mod server;
pub mod utils;

// Exit early if head_batch_num is below this threshold
const BLOCK_NUM_THRESHOLD: u64 = 2;
const RPC_FORWARD_HEADERS_ENV: &str = "RPC_FORWARD_HEADERS";

#[derive(Clone)]
struct ForwardedHeaders(Arc<HeaderMap>);

// Forwarding work moved to a newly spawned task must propagate this context explicitly.
tokio::task_local! {
    static FORWARDED_HEADERS: Arc<HeaderMap>;
}

fn is_unsafe_forward_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "expect"
            | "content-type"
            | "accept"
            | "content-encoding"
            | "accept-encoding"
    )
}

fn parse_forward_header_names(value: Option<&str>) -> HashSet<HeaderName> {
    let Some(value) = value
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("null"))
    else {
        return HashSet::new();
    };

    value
        .split(',')
        .filter_map(|value| {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }

            match HeaderName::from_bytes(value.as_bytes()) {
                Ok(name) if !is_unsafe_forward_header(&name) => Some(name),
                Ok(name) => {
                    tracing::warn!(header = %name, "Ignoring unsafe RPC forward header");
                    None
                }
                Err(error) => {
                    tracing::warn!(header = value, %error, "Ignoring invalid RPC forward header");
                    None
                }
            }
        })
        .collect()
}

pub(crate) fn forward_header_names_from_env() -> Arc<HashSet<HeaderName>> {
    Arc::new(parse_forward_header_names(
        std::env::var(RPC_FORWARD_HEADERS_ENV).ok().as_deref(),
    ))
}

pub(crate) fn capture_forwarded_headers(
    mut request: jsonrpsee::server::HttpRequest,
    configured_headers: &HashSet<HeaderName>,
) -> jsonrpsee::server::HttpRequest {
    if configured_headers.is_empty() {
        return request;
    }

    let mut forwarded_headers = HeaderMap::new();
    for (name, value) in request.headers() {
        if configured_headers.contains(name) {
            forwarded_headers.append(name.clone(), value.clone());
        }
    }

    if !forwarded_headers.is_empty() {
        request
            .extensions_mut()
            .insert(ForwardedHeaders(Arc::new(forwarded_headers)));
    }

    request
}

#[derive(Debug, Clone)]
pub(crate) struct ForwardHeaders<S>(pub S);

impl<'a, S> RpcServiceT<'a> for ForwardHeaders<S>
where
    S: RpcServiceT<'a>,
{
    type Future = Either<S::Future, TaskLocalFuture<Arc<HeaderMap>, S::Future>>;

    fn call(&self, request: Request<'a>) -> Self::Future {
        let forwarded_headers = request
            .extensions()
            .get::<ForwardedHeaders>()
            .map(|headers| Arc::clone(&headers.0));
        let future = self.0.call(request);

        match forwarded_headers {
            Some(headers) => Either::Right(FORWARDED_HEADERS.scope(headers, future)),
            None => Either::Left(future),
        }
    }
}

fn attach_forwarded_headers(mut request: HttpRequest) -> HttpRequest {
    let Ok(forwarded_headers) = FORWARDED_HEADERS.try_with(Arc::clone) else {
        return request;
    };

    for name in forwarded_headers.keys() {
        request.headers_mut().remove(name);
    }
    for (name, value) in forwarded_headers.iter() {
        request.headers_mut().append(name.clone(), value.clone());
    }

    request
}

pub type ForwardingHttpClient = HttpClient<MapRequest<HttpBackend, fn(HttpRequest) -> HttpRequest>>;

pub fn build_forwarding_http_client(
    target: impl AsRef<str>,
) -> Result<ForwardingHttpClient, jsonrpsee::core::client::Error> {
    let middleware = tower::ServiceBuilder::new()
        .map_request(attach_forwarded_headers as fn(HttpRequest) -> HttpRequest);

    HttpClientBuilder::default()
        .set_http_middleware(middleware)
        .build(target)
}

/// Register the healthcheck rpc
pub fn register_healthcheck_rpc<T: Send + Sync + 'static>(
    rpc_methods: &mut RpcModule<T>,
    ledger_db: LedgerDB,
) -> Result<(), RegisterMethodError> {
    let mut rpc = RpcModule::new(ledger_db);

    rpc.register_async_method("health_check", |_, ledger_db, _| async move {
        let error = |msg: &str| {
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(msg.to_string()),
            )
        };

        let Some((L2BlockNumber(head_batch_num), _)) = ledger_db
            .get_head_l2_block()
            .map_err(|err| error(&format!("Failed to get head l2 block: {err}")))?
        else {
            return Ok::<(), ErrorObjectOwned>(());
        };

        if head_batch_num < BLOCK_NUM_THRESHOLD {
            return Ok::<(), ErrorObjectOwned>(());
        }

        let l2_blocks = ledger_db
            .get_l2_block_range(
                &(L2BlockNumber(head_batch_num - 1)..=L2BlockNumber(head_batch_num)),
            )
            .map_err(|err| error(&format!("Failed to get l2 block range: {err}")))?;

        let block_time_s = (l2_blocks[1].timestamp - l2_blocks[0].timestamp).max(1);
        tokio::time::sleep(Duration::from_millis(block_time_s * 1500)).await;

        let (new_head_batch_num, _) = ledger_db
            .get_head_l2_block()
            .map_err(|err| error(&format!("Failed to get head l2 block: {err}")))?
            .unwrap();
        if new_head_batch_num > L2BlockNumber(head_batch_num) {
            Ok::<(), ErrorObjectOwned>(())
        } else {
            Err(error("Block number is not increasing"))
        }
    })?;

    rpc_methods.merge(rpc)
}

/// Register the healthcheck rpc
pub fn register_healthcheck_rpc_light_client_prover<T: Send + Sync + 'static, Da: DaService>(
    rpc_methods: &mut RpcModule<T>,
    da_service: Arc<Da>,
) -> Result<(), RegisterMethodError> {
    let mut rpc = RpcModule::new(da_service.clone());

    rpc.register_async_method("health_check", |_, da_service, _| async move {
        let error = |msg: &str| {
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(msg.to_string()),
            )
        };

        let exponential_backoff = ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(120)),
            ..Default::default()
        };

        let res = retry_backoff(exponential_backoff.clone(), || {
            let da_service = da_service.clone();
            async move {
                da_service.get_head_block_header().await.map_err(|e| {
                    let e = e;
                    backoff::Error::transient(e)
                })
            }
        })
        .await;
        match res {
            Ok(_) => Ok::<(), ErrorObjectOwned>(()),
            Err(e) => Err(error(&format!("Failed to retrieve head block header: {e}"))),
        }
    })?;

    rpc_methods.merge(rpc)
}

/// Returns health check proxy layer to be used as http middleware
pub fn get_healthcheck_proxy_layer() -> ProxyGetRequestLayer {
    ProxyGetRequestLayer::new("/health", "health_check").unwrap()
}

/// Returns cors layer to be used as http middleware
pub fn get_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any)
}

#[derive(Debug, Clone)]
pub struct Logger<S>(pub S);

impl<'a, S> RpcServiceT<'a> for Logger<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'a,
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let req_id = req.id();
        let req_method = req.method_name().to_string();

        tracing::debug!(id = ?req_id, method = ?req_method, params = ?req.params().as_str(), "rpc_request");

        let service = self.0.clone();
        async move {
            let resp = service.call(req).await;
            if resp.is_success() {
                tracing::trace!(id = ?req_id, method = ?req_method, result = ?resp.as_result(), "rpc_success");
            } else {
                match req_method.as_str() {
                    "eth_sendRawTransaction" | "eth_sendRawTransactionSync"=> tracing::debug!(id = ?req_id, method = ?req_method, result = ?resp.as_result(), "rpc_error"),
                    _ => tracing::warn!(id = ?req_id, method = ?req_method, result = ?resp.as_result(), "rpc_error")
                }

            }

            resp
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::Mutex;

    use hyper::header::{HeaderValue, ACCEPT, AUTHORIZATION};
    use jsonrpsee::types::Id;
    use jsonrpsee::ResponsePayload;
    use tokio::sync::Barrier;

    use super::*;

    #[test]
    fn parses_and_captures_forwarded_headers() {
        for value in [
            None,
            Some(""),
            Some("   "),
            Some(", ,"),
            Some("null"),
            Some(" NuLl "),
        ] {
            assert!(parse_forward_header_names(value).is_empty());
        }

        let configured_headers = parse_forward_header_names(Some(
            " X-Trace-ID, x-trace-id, X-Forward-IP, bad header, host, , ",
        ));
        assert_eq!(configured_headers.len(), 2);
        assert!(configured_headers.contains(&HeaderName::from_static("x-trace-id")));
        assert!(configured_headers.contains(&HeaderName::from_static("x-forward-ip")));

        let mut request = jsonrpsee::server::HttpRequest::new(jsonrpsee::server::HttpBody::empty());
        request
            .headers_mut()
            .append("x-trace-id", HeaderValue::from_static("first"));
        request.headers_mut().append(
            "x-trace-id",
            HeaderValue::from_bytes(b"opaque\xfa").unwrap(),
        );
        request
            .headers_mut()
            .insert("x-not-forwarded", HeaderValue::from_static("excluded"));

        let request = capture_forwarded_headers(request, &configured_headers);
        let forwarded_headers = request.extensions().get::<ForwardedHeaders>().unwrap();
        let values = forwarded_headers
            .0
            .get_all("x-trace-id")
            .iter()
            .map(HeaderValue::as_bytes)
            .collect::<Vec<_>>();

        assert_eq!(values, vec![b"first".as_slice(), b"opaque\xfa".as_slice()]);
        assert!(!forwarded_headers.0.contains_key("x-not-forwarded"));
        assert_eq!(request.headers().get_all("x-trace-id").iter().count(), 2);

        let request = capture_forwarded_headers(
            jsonrpsee::server::HttpRequest::new(jsonrpsee::server::HttpBody::empty()),
            &configured_headers,
        );
        assert!(request.extensions().get::<ForwardedHeaders>().is_none());
    }

    #[tokio::test]
    async fn attaches_forwarded_headers_and_is_noop_without_context() {
        let mut request = HttpRequest::new(jsonrpsee::http_client::HttpBody::empty());
        request
            .headers_mut()
            .insert(ACCEPT, HeaderValue::from_static("application/json"));
        request
            .headers_mut()
            .insert(AUTHORIZATION, HeaderValue::from_static("original"));
        let original_headers = request.headers().clone();

        let request = attach_forwarded_headers(request);
        assert_eq!(request.headers(), &original_headers);

        let mut forwarded_headers = HeaderMap::new();
        forwarded_headers.append(AUTHORIZATION, HeaderValue::from_static("first"));
        forwarded_headers.append(AUTHORIZATION, HeaderValue::from_static("second"));

        let request = FORWARDED_HEADERS
            .scope(Arc::new(forwarded_headers), async move {
                attach_forwarded_headers(request)
            })
            .await;
        let authorization_values = request
            .headers()
            .get_all(AUTHORIZATION)
            .iter()
            .map(HeaderValue::as_bytes)
            .collect::<Vec<_>>();

        assert_eq!(
            authorization_values,
            vec![b"first".as_slice(), b"second".as_slice()]
        );
        assert_eq!(
            request.headers().get(ACCEPT),
            Some(&HeaderValue::from_static("application/json"))
        );
    }

    type ObservedHeaders = Vec<(u64, Vec<Vec<u8>>)>;

    #[derive(Clone)]
    struct InspectForwardedHeaders {
        barrier: Arc<Barrier>,
        observed: Arc<Mutex<ObservedHeaders>>,
    }

    impl<'a> RpcServiceT<'a> for InspectForwardedHeaders {
        type Future = BoxFuture<'a, MethodResponse>;

        fn call(&self, request: Request<'a>) -> Self::Future {
            let id = *request.id().as_number().unwrap();
            let barrier = Arc::clone(&self.barrier);
            let observed = Arc::clone(&self.observed);

            async move {
                barrier.wait().await;
                let request = attach_forwarded_headers(HttpRequest::new(
                    jsonrpsee::http_client::HttpBody::empty(),
                ));
                let values = request
                    .headers()
                    .get_all("x-trace-id")
                    .iter()
                    .map(|value| value.as_bytes().to_vec())
                    .collect();
                observed.lock().unwrap().push((id, values));

                MethodResponse::response(Id::Number(id), ResponsePayload::success(()), usize::MAX)
            }
            .boxed()
        }
    }

    fn request_with_forwarded_header(id: u64, value: &'static str) -> Request<'static> {
        let mut request = Request::new(Cow::Borrowed("test"), None, Id::Number(id));
        let mut headers = HeaderMap::new();
        headers.insert("x-trace-id", HeaderValue::from_static(value));
        request
            .extensions_mut()
            .insert(ForwardedHeaders(Arc::new(headers)));
        request
    }

    #[tokio::test]
    async fn isolates_forwarded_headers_between_requests() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let service = ForwardHeaders(InspectForwardedHeaders {
            barrier: Arc::new(Barrier::new(2)),
            observed: Arc::clone(&observed),
        });

        let first = service.call(request_with_forwarded_header(1, "first"));
        let second = service.call(request_with_forwarded_header(2, "second"));
        tokio::join!(first, second);

        let mut observed = observed.lock().unwrap().clone();
        observed.sort_by_key(|(id, _)| *id);
        assert_eq!(
            observed,
            vec![(1, vec![b"first".to_vec()]), (2, vec![b"second".to_vec()])]
        );
        assert!(FORWARDED_HEADERS.try_with(|_| ()).is_err());
    }
}
