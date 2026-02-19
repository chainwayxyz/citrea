use sov_db::schema::types::da_jobs::JobId;

use crate::helpers::get_timestamp;

/// Calculates elapsed time since job creation using job uuidv7
pub fn get_job_elapsed_time(job_id: JobId) -> u64 {
    let job_created_at = job_id.get_timestamp().map(|ts| ts.to_unix().0).unwrap_or(0);

    get_timestamp().saturating_sub(job_created_at)
}
