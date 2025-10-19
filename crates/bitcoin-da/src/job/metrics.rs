use std::sync::LazyLock;

use metrics::{Counter, Gauge, Histogram};
use metrics_derive::Metrics;
use sov_db::schema::types::da_jobs::{DaJobStatus, JobProgress};

use crate::helpers::get_timestamp;

/// Defines the metrics being collected for the DA job service
#[derive(Metrics)]
#[metrics(scope = "da_job")]
pub struct DaJobMetrics {
    /// Number of pending jobs
    #[metric(describe = "Number of jobs in pending status")]
    pub jobs_pending: Gauge,

    /// Number of in-progress jobs
    #[metric(describe = "Number of jobs in progress status")]
    pub jobs_in_progress: Gauge,

    /// Number of completed jobs
    #[metric(describe = "Number of jobs in completed status")]
    pub jobs_completed: Gauge,

    /// Number of cancelled jobs
    #[metric(describe = "Number of jobs in cancelled status")]
    pub jobs_cancelled: Gauge,

    /// Number of failed jobs
    #[metric(describe = "Number of jobs in failed status")]
    pub jobs_failed: Gauge,

    /// Total jobs submitted
    #[metric(describe = "Total number of jobs submitted")]
    pub jobs_submitted_total: Counter,

    /// Total jobs completed successfully
    #[metric(describe = "Total number of jobs completed successfully")]
    pub jobs_completed_total: Counter,

    /// Total jobs cancelled
    #[metric(describe = "Total number of jobs cancelled")]
    pub jobs_cancelled_total: Counter,

    /// Total jobs failed
    #[metric(describe = "Total number of jobs failed")]
    pub jobs_failed_total: Counter,

    /// Time taken to process a job from pending to completion
    #[metric(describe = "Duration from job submission to completion in seconds")]
    pub job_processing_duration: Histogram,

    /// Number of chunks sent per job
    #[metric(describe = "Number of commit/reveal pairs sent per job")]
    pub job_chunks_sent: Histogram,

    /// Size of job data in bytes
    #[metric(describe = "Size of job data in bytes")]
    pub job_data_size: Histogram,
}

impl DaJobMetrics {
    pub fn record_status_update(&self, old_status: &DaJobStatus, progress: &JobProgress) {
        let new_status = &progress.status;
        if old_status == new_status {
            return;
        }

        match old_status {
            DaJobStatus::Pending => self.jobs_pending.decrement(1.0),
            DaJobStatus::InProgress => self.jobs_in_progress.decrement(1.0),
            DaJobStatus::Completed => self.jobs_completed.decrement(1.0),
            DaJobStatus::Cancelled => self.jobs_cancelled.decrement(1.0),
            DaJobStatus::Failed { .. } => self.jobs_failed.decrement(1.0),
        }

        match new_status {
            DaJobStatus::Pending => {
                self.jobs_pending.increment(1.0);
            }
            DaJobStatus::InProgress => {
                self.jobs_in_progress.increment(1.0);
            }
            DaJobStatus::Completed => {
                self.jobs_completed.increment(1.0);
                self.jobs_completed_total.increment(1);

                // Total time between job creation and completion
                if let Some(created_at) = progress.job_id.get_timestamp() {
                    let duration = get_timestamp().saturating_sub(created_at.to_unix().0);
                    self.job_processing_duration.record(duration as f64);
                }

                // Record total chunks sent
                self.job_chunks_sent
                    .record(progress.sent_chunks.count() as f64);
            }
            DaJobStatus::Cancelled => {
                self.jobs_cancelled.increment(1.0);
                self.jobs_cancelled_total.increment(1);
            }
            DaJobStatus::Failed { .. } => {
                self.jobs_failed.increment(1.0);
                self.jobs_failed_total.increment(1);
            }
        }
    }

    /// Record a job submission
    pub fn record_job_submitted(&self, data_size: usize) {
        self.jobs_submitted_total.increment(1);
        self.jobs_pending.increment(1.0);
        self.job_data_size.record(data_size as f64);
    }
}

/// DA job service metrics
pub static DA_JOB_METRICS: LazyLock<DaJobMetrics> = LazyLock::new(|| {
    DaJobMetrics::describe();
    DaJobMetrics::default()
});
