use std::future::Future;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// TaskManager manages tasks spawned using tokio and keeps
/// track of handles so that these tasks are cancellable.
/// This provides a way to implement graceful shutdown of our
/// nodes by completing tasks as such read/write to DBs and then
/// performing the shutdown so that the database does not get corrupted.
pub struct TaskManager<T: Send> {
    handles: Vec<JoinHandle<T>>,
    cancellation_token: CancellationToken,
}

impl<T: Send + 'static> TaskManager<T> {
    pub fn new() -> Self {
        Self {
            handles: vec![],
            cancellation_token: CancellationToken::new(),
        }
    }

    /// Spawn a new asynchronous task.
    pub fn spawn(&mut self, future: impl Future<Output = T> + Send + 'static) {
        let handle = tokio::spawn(future);
        self.handles.push(handle);
    }

    /// Drastically abort all running tasks
    pub fn abort(&self) {
        self.cancellation_token.cancel();
        for handle in &self.handles {
            handle.abort();
        }
    }

    /// Provides a child cancellation token.
    ///
    /// This would enable us to pass this token into child tasks
    /// so that all child tasks can be cancelled at once.
    pub fn child_token(&self) -> CancellationToken {
        self.cancellation_token.child_token()
    }
}
