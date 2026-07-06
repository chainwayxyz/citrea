use std::borrow::Cow;
use std::future::Future;

use jsonrpsee::server::middleware::rpc::{
    Batch, BatchEntry, BatchEntryErr, MethodResponse, Notification, Request, RpcServiceT,
};
use jsonrpsee::types::error::ErrorObjectOwned;
use serde_json::value::RawValue;
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

impl<S> RpcServiceT for Auth<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            NotificationResponse = MethodResponse,
            BatchResponse = MethodResponse,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    type BatchResponse = MethodResponse;

    fn call<'a>(&self, req: Request<'a>) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let service = self.service.clone();
        let api_key = self.api_key.clone().map(Value::from);
        async move {
            let req_id = req.id().clone();
            match authorize_request(req, api_key.as_ref()) {
                Ok(req) => service.call(req).await,
                Err(err) => MethodResponse::error(req_id, err),
            }
        }
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        let service = self.service.clone();
        let api_key = self.api_key.clone().map(Value::from);
        async move {
            let mut entries = Vec::with_capacity(batch.len());
            let mut saw_notification = false;

            for batch_entry in batch {
                match batch_entry {
                    Ok(BatchEntry::Call(req)) => {
                        let req_id = req.id().clone();
                        match authorize_request(req, api_key.as_ref()) {
                            Ok(req) => entries.push(Ok(BatchEntry::Call(req))),
                            Err(err) => entries.push(Err(BatchEntryErr::new(req_id, err))),
                        }
                    }
                    Ok(BatchEntry::Notification(notification)) => {
                        saw_notification = true;
                        if let Some(notification) =
                            authorize_notification(notification, api_key.as_ref())
                        {
                            entries.push(Ok(BatchEntry::Notification(notification)));
                        }
                    }
                    Err(err) => entries.push(Err(err)),
                }
            }

            if entries.is_empty() && saw_notification {
                MethodResponse::notification()
            } else {
                service.batch(Batch::from(entries)).await
            }
        }
    }

    fn notification<'a>(
        &self,
        notification: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        let service = self.service.clone();
        let api_key = self.api_key.clone().map(Value::from);
        async move {
            match authorize_notification(notification, api_key.as_ref()) {
                Some(notification) => service.notification(notification).await,
                None => MethodResponse::notification(),
            }
        }
    }
}

fn authorize_request<'a>(
    req: Request<'a>,
    api_key: Option<&Value>,
) -> Result<Request<'a>, ErrorObjectOwned> {
    if !is_protected_method(req.method_name()) {
        return Ok(req);
    }

    let Some(api_key) = api_key else {
        return Err(cannot_access_protected_method());
    };

    let (req, auth_param) = remove_last_request_param(req);
    match auth_param {
        Some(key) if &key == api_key => Ok(req),
        _ => Err(invalid_or_missing_api_key()),
    }
}

fn authorize_notification<'a>(
    notification: Notification<'a>,
    api_key: Option<&Value>,
) -> Option<Notification<'a>> {
    if !is_protected_method(notification.method_name()) {
        return Some(notification);
    }

    let api_key = api_key?;

    let (notification, auth_param) = remove_last_notification_param(notification);
    match auth_param {
        Some(key) if &key == api_key => Some(notification),
        _ => None,
    }
}

fn is_protected_method(method: &str) -> bool {
    PROTECTED_METHODS.contains(&method)
}

fn cannot_access_protected_method() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(401, "Cannot access protected method", None::<String>)
}

fn invalid_or_missing_api_key() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(401, "Invalid or missing API key", None::<String>)
}

// Extracts the last parameter from a JSON-RPC request.
// Returns a new request without the last parameter and the last parameter itself.
// If params is not an array, it returns the request with params cleared.
fn remove_last_request_param<'a>(req: Request<'a>) -> (Request<'a>, Option<Value>) {
    let (params, last_param) = remove_last_raw_param(req.params);
    let new_req = Request {
        jsonrpc: req.jsonrpc,
        id: req.id,
        method: req.method,
        params,
        extensions: req.extensions,
    };
    (new_req, last_param)
}

// Extracts the last parameter from a JSON-RPC notification.
// Returns a new notification without the last parameter and the last parameter itself.
// If params is not an array, it returns the notification with params cleared.
fn remove_last_notification_param<'a>(
    notification: Notification<'a>,
) -> (Notification<'a>, Option<Value>) {
    let (params, last_param) = remove_last_raw_param(notification.params);
    let new_notification = Notification {
        jsonrpc: notification.jsonrpc,
        method: notification.method,
        params,
        extensions: notification.extensions,
    };
    (new_notification, last_param)
}

fn remove_last_raw_param<'a>(
    params: Option<Cow<'a, RawValue>>,
) -> (Option<Cow<'a, RawValue>>, Option<Value>) {
    match params {
        Some(params) => match serde_json::from_str::<Vec<Value>>(params.get()) {
            Ok(mut params) => {
                let last_param = params.pop();
                let params = serde_json::to_string(&params).expect("Can't fail");
                let params_box = RawValue::from_string(params).expect("Can't fail");
                (Some(Cow::Owned(params_box)), last_param)
            }
            Err(_) => (None, None),
        },
        None => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use jsonrpsee::types::Id;

    use super::*;

    #[derive(Default, Debug)]
    struct Seen {
        protected_calls_in_batch: usize,
        protected_notifications_in_batch: usize,
        batch_errs: usize,
        notifications_forwarded: usize,
        last_call_params_len: Option<usize>,
        last_notification_params_len: Option<usize>,
    }

    #[derive(Debug, Clone)]
    struct DummyService {
        seen: Arc<Mutex<Seen>>,
    }

    impl RpcServiceT for DummyService {
        type MethodResponse = MethodResponse;
        type NotificationResponse = MethodResponse;
        type BatchResponse = MethodResponse;

        fn call<'a>(
            &self,
            req: Request<'a>,
        ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
            let seen = self.seen.clone();
            async move {
                seen.lock().expect("lock poisoned").last_call_params_len = req
                    .params()
                    .parse::<Vec<Value>>()
                    .ok()
                    .map(|params| params.len());
                MethodResponse::error(
                    req.id().clone(),
                    ErrorObjectOwned::owned(777, "inner call", None::<String>),
                )
            }
        }

        fn batch<'a>(
            &self,
            batch: Batch<'a>,
        ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
            let seen = self.seen.clone();
            async move {
                let mut seen = seen.lock().expect("lock poisoned");
                for entry in batch {
                    match entry {
                        Ok(BatchEntry::Call(req)) => {
                            if is_protected_method(req.method_name()) {
                                seen.protected_calls_in_batch += 1;
                            }
                            seen.last_call_params_len = req
                                .params()
                                .parse::<Vec<Value>>()
                                .ok()
                                .map(|params| params.len());
                        }
                        Ok(BatchEntry::Notification(notification)) => {
                            if is_protected_method(notification.method_name()) {
                                seen.protected_notifications_in_batch += 1;
                            }
                            seen.last_notification_params_len = notification
                                .params()
                                .as_ref()
                                .and_then(|params| {
                                    serde_json::from_str::<Vec<Value>>(params.get()).ok()
                                })
                                .map(|params| params.len());
                        }
                        Err(_) => {
                            seen.batch_errs += 1;
                        }
                    }
                }

                MethodResponse::notification()
            }
        }

        fn notification<'a>(
            &self,
            notification: Notification<'a>,
        ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
            let seen = self.seen.clone();
            async move {
                let mut seen = seen.lock().expect("lock poisoned");
                seen.notifications_forwarded += 1;
                seen.last_notification_params_len = notification
                    .params()
                    .as_ref()
                    .and_then(|params| serde_json::from_str::<Vec<Value>>(params.get()).ok())
                    .map(|params| params.len());
                MethodResponse::notification()
            }
        }
    }

    fn raw(value: &str) -> Box<RawValue> {
        RawValue::from_string(value.to_string()).expect("valid raw value")
    }

    #[test]
    fn batch_rejects_protected_calls_without_api_key() {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let service = DummyService { seen: seen.clone() };
        let auth = Auth::new(service, None);

        let mut batch = Batch::new();
        batch.push(Request::owned(
            "backup_info".to_string(),
            Some(raw(r#"["/tmp/backup","secret"]"#)),
            Id::Number(1),
        ));

        futures::executor::block_on(auth.batch(batch));

        let seen = seen.lock().expect("lock poisoned");
        assert_eq!(seen.protected_calls_in_batch, 0);
        assert_eq!(seen.batch_errs, 1);
    }

    #[test]
    fn batch_allows_protected_calls_with_valid_api_key_and_strips_key() {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let service = DummyService { seen: seen.clone() };
        let auth = Auth::new(service, Some("secret".to_string()));

        let mut batch = Batch::new();
        batch.push(Request::owned(
            "backup_info".to_string(),
            Some(raw(r#"["/tmp/backup","secret"]"#)),
            Id::Number(1),
        ));

        futures::executor::block_on(auth.batch(batch));

        let seen = seen.lock().expect("lock poisoned");
        assert_eq!(seen.protected_calls_in_batch, 1);
        assert_eq!(seen.batch_errs, 0);
        assert_eq!(seen.last_call_params_len, Some(1));
    }

    #[test]
    fn notification_rejects_protected_method_without_api_key() {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let service = DummyService { seen: seen.clone() };
        let auth = Auth::new(service, None);

        let notification = Notification::new(
            Cow::Borrowed("backup_info"),
            Some(Cow::Owned(raw(r#"["/tmp/backup","secret"]"#))),
        );

        futures::executor::block_on(auth.notification(notification));

        let seen = seen.lock().expect("lock poisoned");
        assert_eq!(seen.notifications_forwarded, 0);
    }

    #[test]
    fn notification_allows_protected_method_with_valid_api_key_and_strips_key() {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let service = DummyService { seen: seen.clone() };
        let auth = Auth::new(service, Some("secret".to_string()));

        let notification = Notification::new(
            Cow::Borrowed("backup_info"),
            Some(Cow::Owned(raw(r#"["/tmp/backup","secret"]"#))),
        );

        futures::executor::block_on(auth.notification(notification));

        let seen = seen.lock().expect("lock poisoned");
        assert_eq!(seen.notifications_forwarded, 1);
        assert_eq!(seen.last_notification_params_len, Some(1));
    }
}
