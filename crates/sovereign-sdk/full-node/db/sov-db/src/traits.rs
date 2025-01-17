use std::path::Path;
use std::sync::{Arc, RwLock};

/// Backup database
pub trait Backup: Send + Sync {
    /// Backup a database at <backup_path>
    fn backup(&self, backup_path: &Path) -> anyhow::Result<()>;
}

impl<T: Backup> Backup for Arc<RwLock<T>> {
    fn backup(&self, backup_path: &std::path::Path) -> anyhow::Result<()> {
        self.read().unwrap().backup(backup_path)
    }
}
