use futures::future::BoxFuture;
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::types::error::ErrorObjectOwned;
use jsonrpsee::types::Request;
use jsonrpsee::MethodResponse;
use serde_json::Value;

const PROTECTED_METHODS: [&str; 3] = ["backup_create", "backup_validate", "backup_info"];

#[derive(Debug, Clone)]
pub struct Auth<S> {
    service: S,
    api_key: Option<String>,
}

impl<S> Auth<S> {
    pub fn new(service: S, api_key: Option<String>) -> Self {
        Self { service, api_key }
    }
}

impl<'a, S> RpcServiceT<'a> for Auth<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'a,
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let method = req.method_name();
        let service = self.service.clone();
        let api_key = self.api_key.clone().map(Value::from);

        if !PROTECTED_METHODS.contains(&method) {
            return Box::pin(service.call(req));
        }

        let Some(api_key) = api_key else {
            return Box::pin(async move {
                MethodResponse::error(
                    req.id().clone(),
                    ErrorObjectOwned::owned(401, "Cannot access protected method", None::<String>),
                )
            });
        };

        Box::pin(async move {
            let params = req.params();

            let auth_param = params
                .parse::<Vec<Value>>()
                .ok()
                .and_then(|v| v.last().cloned());

            match auth_param {
                Some(key) if key == api_key => service.call(req).await,
                _ => MethodResponse::error(
                    req.id().clone(),
                    ErrorObjectOwned::owned(401, "Invalid or missing API key", None::<String>),
                ),
            }
        })
    }
}
