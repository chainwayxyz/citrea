use std::future::Future;

use tokio::task::JoinHandle;

pub struct TaskManager<T: Send> {
    handles: Vec<JoinHandle<T>>,
}

impl<T: Send + 'static> TaskManager<T> {
    pub fn new() -> Self {
        Self { handles: vec![] }
    }

    pub fn spawn(&mut self, future: impl Future<Output = T> + Send + 'static) {
        let handle = tokio::spawn(future);
        self.handles.push(handle);
    }

    pub fn abort(&self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}
