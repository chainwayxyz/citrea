use std::future::Future;

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// TaskManager manages tasks spawned using tokio and keeps
/// track of handles so that these tasks are cancellable.
/// This provides a way to implement graceful shutdown of our
/// nodes by completing tasks as such read/write to DBs and then
/// performing the shutdown so that the database does not get corrupted.
pub struct TaskManager<T: Send> {
    task_tracker: TaskTracker,
    cancellation_token: CancellationToken,
}

impl<T: Send + 'static> TaskManager<T> {
    pub fn new() -> Self {
        Self {
            task_tracker: TaskTracker::new(),
            cancellation_token: CancellationToken::new(),
        }
    }

    /// Spawn a new asynchronous task.
    pub fn spawn(&mut self, future: impl Future<Output = T> + Send + 'static) {
        self.task_tracker.spawn(future);
    }

    /// Wait for current tasks to finish and stop running them.
    pub async fn abort(&self) {
        self.task_tracker.close();
        self.task_tracker.wait().await;
    }

    /// Provides a child cancellation token.
    ///
    /// This would enable us to pass this token into child tasks
    /// so that all child tasks can be cancelled at once.
    pub fn child_token(&self) -> CancellationToken {
        self.cancellation_token.child_token()
    }
}
