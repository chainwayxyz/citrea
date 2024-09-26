use std::num::NonZeroUsize;

use lru::LruCache;
use sov_rollup_interface::services::da::DaService;

pub struct L1BlockCache<Da>(pub LruCache<u64, Da::FilteredBlock>)
where
    Da: DaService;

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
        Self(LruCache::new(NonZeroUsize::new(10).unwrap()))
    }

    pub fn get(&mut self, height: &u64) -> Option<&Da::FilteredBlock> {
        self.0.get(height)
    }

    pub fn put(&mut self, height: u64, block: Da::FilteredBlock) {
        self.0.put(height, block);
    }
}
