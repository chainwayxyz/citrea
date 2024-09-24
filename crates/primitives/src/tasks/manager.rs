use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

const WAIT_DURATION: u64 = 5; // 5 seconds

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
    ///
    /// Tasks are forced to accept a cancellation token so that they can be notified
    /// about the cancellation using the passed token.
    pub fn spawn<F, Fut>(&mut self, callback: F)
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = T> + Send + 'static,
    {
        let handle = tokio::spawn(callback(self.child_token()));
        self.handles.push(handle);
    }

    /// Notify all running tasks to stop.
    pub async fn abort(&self) {
        self.cancellation_token.cancel();

        // provide tasks with some time to finish existing work
        sleep(Duration::from_secs(WAIT_DURATION)).await;
    }

    /// Provides a child cancellation token.
    ///
    /// This would enable us to pass this token into child tasks
    /// so that all child tasks can be cancelled at once.
    pub fn child_token(&self) -> CancellationToken {
        self.cancellation_token.child_token()
    }
}
