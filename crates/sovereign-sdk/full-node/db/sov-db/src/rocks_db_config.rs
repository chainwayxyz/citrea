// Adapted from Aptos-Core.
// Modified to remove serde dependency
use std::path::Path;

use rlimit::{getrlimit, Resource};
use rocksdb::{BlockBasedOptions, Cache, Options};
use tracing::warn;

/// Port selected RocksDB options for tuning underlying rocksdb instance of our state db.
/// The current default values are taken from Aptos. TODO: tune rocksdb for our workload.
/// see <https://github.com/facebook/rocksdb/blob/master/include/rocksdb/options.h>
/// for detailed explanations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RocksdbConfig<'a> {
    /// The path to the RocksDB database.
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
        let max_open_files = max_open_files.unwrap_or_else(get_fd_limit);
        Self {
            path,
            // Allow db to close old sst files, saving memory.
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

        let mut block_based_options = BlockBasedOptions::default();
        /*
         * The following settings are recommended in:
         * https://github.com/facebook/rocksdb/wiki/memory-usage-in-rocksdb
         */
        // Enable read caching with a specific capacity.
        // The initial capacity is set to a larger default. However, setting the capacity
        // would NOT prevent rocksdb from exceeding this capacity unless `strict_capacity_limit` is set.
        // However, the rocksdb rust binding does not expose this functionality. This means that we
        // could still have OOM errors when trying to allocate more for the cache even if the capacity
        // is reached.
        let cache = Cache::new_lru_cache(100 * 1024 * 1024); // 100 MB
        block_based_options.set_block_cache(&cache);
        // jemalloc friendly bloom filter sizing
        block_based_options.set_optimize_filters_for_memory(true);
        // By default our block size is 4KB, we set this to 32KB.
        // Increasing the size of the block decreases the number of blocks,
        // therefore, less memory consumption for indicies.
        block_based_options.set_block_size(32 * 1024);
        // Default is Snappy but Lz4 is recommend
        // https://github.com/facebook/rocksdb/wiki/Compression
        db_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        db_opts.set_compression_options_parallel_threads(4);

        db_opts.set_max_open_files(self.max_open_files);
        db_opts.set_max_total_wal_size(self.max_total_wal_size);
        db_opts.set_max_background_jobs(self.max_background_jobs);
        if !readonly {
            // Increase write buffer size to reduce allocations.
            db_opts.set_write_buffer_size(30 * 1024 * 1024); // 30 MB
            db_opts.set_block_based_table_factory(&block_based_options);

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
