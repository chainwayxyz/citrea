use std::collections::HashMap;
use std::future::Future;
use std::time::Instant;

use jsonrpsee::server::middleware::rpc::{
    Batch, BatchEntry, MethodResponse, Notification, Request, RpcServiceT,
};
use metrics::{counter, histogram};
use serde_json::Value;

/// Wraps an inner RPC service and records response times
#[derive(Debug, Clone)]
pub struct RpcMetrics<S>(pub S);

impl<S> RpcServiceT for RpcMetrics<S>
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
        let service = self.0.clone();
        let method_name = req.method_name().to_string();
        let start = Instant::now();

        async move {
            let response = service.call(req).await;

            let elapsed = start.elapsed().as_secs_f64();
            let success = response.is_success();
            record_rpc_metrics(method_name, success, elapsed);

            response
        }
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        let service = self.0.clone();
        let calls: Vec<(String, String)> = batch
            .iter()
            .filter_map(|entry| match entry {
                Ok(BatchEntry::Call(req)) => {
                    let id =
                        serde_json::to_string(&req.id()).unwrap_or_else(|_| req.id().to_string());
                    Some((id, req.method_name().to_string()))
                }
                _ => None,
            })
            .collect();
        let start = Instant::now();

        async move {
            let response = service.batch(batch).await;
            let elapsed = start.elapsed().as_secs_f64();
            if calls.is_empty() {
                record_rpc_metrics("batch".to_string(), is_batch_success(&response), elapsed);
            } else {
                let success_by_id = batch_call_success_by_id(&response);
                let batch_success = is_batch_success(&response);

                for (id, method_name) in calls {
                    let success = success_by_id
                        .as_ref()
                        .and_then(|success_by_id| success_by_id.get(&id).copied())
                        .unwrap_or(batch_success);
                    record_rpc_metrics(method_name, success, elapsed);
                }
            }

            response
        }
    }

    fn notification<'a>(
        &self,
        notification: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        self.0.notification(notification)
    }
}

fn record_rpc_metrics(method_name: String, success: bool, elapsed: f64) {
    let success = success.to_string();
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
}

fn is_batch_success(response: &MethodResponse) -> bool {
    if response.is_notification() {
        return true;
    }
    if !response.is_batch() {
        return response.is_success();
    }

    let Ok(value) = serde_json::from_str::<Value>(response.as_json().get()) else {
        return response.is_success();
    };

    match value {
        Value::Array(entries) => entries.iter().all(|entry| match entry {
            Value::Object(entry) => !entry.contains_key("error"),
            _ => false,
        }),
        Value::Object(entry) => !entry.contains_key("error"),
        _ => false,
    }
}

fn batch_call_success_by_id(response: &MethodResponse) -> Option<HashMap<String, bool>> {
    if !response.is_batch() {
        return None;
    }

    let Ok(value) = serde_json::from_str::<Value>(response.as_json().get()) else {
        return None;
    };
    let Value::Array(entries) = value else {
        return None;
    };

    let mut success_by_id = HashMap::new();
    for entry in entries {
        let Value::Object(entry) = entry else {
            continue;
        };

        let Some(id) = entry.get("id") else {
            continue;
        };

        let Ok(id) = serde_json::to_string(id) else {
            continue;
        };

        success_by_id.insert(id, !entry.contains_key("error"));
    }

    Some(success_by_id)
}
