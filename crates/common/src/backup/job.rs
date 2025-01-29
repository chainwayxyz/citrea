use super::{BackupManager, CreateBackupInfo};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::LedgerDB;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tokio::sync::{Mutex, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running {
        started_at: u64,
    },
    Completed {
        started_at: u64,
        completed_at: u64,
        result: CreateBackupInfo,
    },
    Failed {
        started_at: u64,
        failed_at: u64,
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupJob {
    id: u32,
    status: JobStatus,
    path: PathBuf,
}

pub struct JobManager {
    next_job_id: AtomicU32,
    jobs: Arc<RwLock<HashMap<u32, BackupJob>>>,
    backup_manager: Arc<BackupManager>,
    ledger_db: LedgerDB,
    backup_lock: Arc<Mutex<()>>,
}

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

impl JobManager {
    pub fn new(backup_manager: Arc<BackupManager>, ledger_db: LedgerDB) -> Self {
        Self {
            next_job_id: AtomicU32::new(1),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            backup_manager,
            ledger_db,
            backup_lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn create_backup_job(&self, path: Option<PathBuf>) -> anyhow::Result<u32> {
        let backup_path = path
            .or_else(|| self.backup_manager.base_path.clone())
            .context("Missing path and no backup_path found in config.")?;

        let job_id = self.next_job_id.fetch_add(1, Ordering::SeqCst);
        let job = BackupJob {
            id: job_id,
            status: JobStatus::Pending,
            path: backup_path.clone(),
        };
        self.jobs.write().await.insert(job_id, job);

        let backup_manager = self.backup_manager.clone();
        let jobs = self.jobs.clone();
        let ledger_db = self.ledger_db.clone();
        let backup_lock = self.backup_lock.clone();

        tokio::spawn(async move {
            // Ensure sequential backups
            let _backup_guard = backup_lock.lock().await;

            let started_at = get_timestamp();
            {
                let mut jobs = jobs.write().await;
                if let Some(job) = jobs.get_mut(&job_id) {
                    job.status = JobStatus::Running { started_at };
                }
            }

            let res = backup_manager.create_backup(backup_path, ledger_db).await;
            let mut jobs = jobs.write().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                match res {
                    Ok(result) => {
                        job.status = JobStatus::Completed {
                            started_at,
                            completed_at: get_timestamp(),
                            result,
                        };
                    }
                    Err(e) => {
                        job.status = JobStatus::Failed {
                            started_at,
                            failed_at: get_timestamp(),
                            error: e.to_string(),
                        };
                    }
                }
            }
        });

        Ok(job_id)
    }

    pub async fn get_job_status(&self, job_id: u32) -> Option<BackupJob> {
        self.jobs.read().await.get(&job_id).cloned()
    }

    pub async fn list_jobs(&self) -> Vec<BackupJob> {
        self.jobs.read().await.values().cloned().collect()
    }
}
