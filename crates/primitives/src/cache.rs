use std::num::NonZeroUsize;

use lru::LruCache;
use sov_rollup_interface::services::da::DaService;

pub struct L1BlockCache<Da>
where
    Da: DaService,
{
    pub by_number: LruCache<u64, Da::FilteredBlock>,
    pub by_hash: LruCache<[u8; 32], Da::FilteredBlock>,
}

impl<Da> Default for L1BlockCache<Da>
where
    Da: DaService,
 {
    fn default() -> Self {
        Self::new()
    }
}

impl<Da> L1BlockCache<Da>
where
    Da: DaService,
{
    pub fn new() -> Self {
        Self {
            by_number: LruCache::new(NonZeroUsize::new(10).unwrap()),
            by_hash: LruCache::new(NonZeroUsize::new(10).unwrap()),
        }
    }
}
