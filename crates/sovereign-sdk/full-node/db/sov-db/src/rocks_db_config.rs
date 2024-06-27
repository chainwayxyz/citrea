// Adapted from Aptos-Core.
// Modified to remove serde dependency

use rlimit::{getrlimit, Resource};
use rocksdb::Options;
use std::path::Path;
use tracing::warn;

/// Port selected RocksDB options for tuning underlying rocksdb instance of our state db.
/// The current default values are taken from Aptos. TODO: tune rocksdb for our workload.
/// see <https://github.com/facebook/rocksdb/blob/master/include/rocksdb/options.h>
/// for detailed explanations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RocksdbConfig<'a> {
    /// Path to the RocksDB file
    pub path: &'a Path,
    /// The maximum number of files that can be open concurrently. Defaults to operating system limit.
    /// In the case of not being able to read from the operating system, it defaults to 256.
    pub max_open_files: i32,
    /// Once write-ahead logs exceed this size, RocksDB will start forcing the flush of column
    /// families whose memtables are backed by the oldest live WAL file. Defaults to 1GB
    pub max_total_wal_size: u64,
    /// The maximum number of background threads, including threads for flushing and compaction. Defaults to 16.
    pub max_background_jobs: i32,
}

impl<'a> RocksdbConfig<'a> {
    /// Creates new instance of [`RocksdbConfig`]
    pub fn new(path: &'a Path, max_open_files: Option<i32>) -> Self {
        let max_open_files = max_open_files.unwrap_or_else(|| get_fd_limit());
        Self {
            path,
            // Allow db to close old sst files, saving memory.
            // TODO: in case of multiple RocksDB instances, there is still a possibility of going over the limit, fix that.
            max_open_files,
            // For now we set the max total WAL size to be 1G. This config can be useful when column
            // families are updated at non-uniform frequencies.
            max_total_wal_size: 1u64 << 30,
            // This includes threads for flushing and compaction. Rocksdb will decide the # of
            // threads to use internally.
            max_background_jobs: 16,
        }
    }

    /// Build [`rocksdb::Options`] from [`RocksdbConfig`]
    pub fn as_rocksdb_options(&self, readonly: bool) -> Options {
        let mut db_opts = Options::default();
        db_opts.set_max_open_files(self.max_open_files);
        db_opts.set_max_total_wal_size(self.max_total_wal_size);
        db_opts.set_max_background_jobs(self.max_background_jobs);
        if !readonly {
            db_opts.create_if_missing(true);
            db_opts.create_missing_column_families(true);
            db_opts.set_atomic_flush(true);
        }

        db_opts
    }
}

fn get_fd_limit() -> i32 {
    let (soft_limit, _) = getrlimit(Resource::NOFILE).unwrap_or_else(|err| {
        warn!(
            "Failed to retrieve max open file limit from the os, defaulting to 256. err={}",
            err
        );
        // Default is 256 due to it being the lowest default limit among operating systems, namely OSX.
        (256, 0)
    });

    if soft_limit > (i32::MAX as u64) {
        i32::MAX
    } else {
        soft_limit as i32
    }
}
