//! Size accounting for the block trace cache.
//!
//! An entry in the cache is a whole block's traces, which is anything from a few hundred bytes to
//! several gigabytes: the call frames of a block keep a copy of the call data of every call made in
//! it, and a single transaction is allowed to retain up to the configured tracing memory limit.
//! Bounding the cache by the number of entries therefore bounds nothing.
//!
//! [`schnellru::ByMemoryUsage`] does not help either: it only accounts for the map's own table,
//! where each of these values is a 24 byte `Vec` header no matter how much heap it owns, and its
//! `is_over_the_limit` is hardcoded to `false`.

use alloy_rpc_types_trace::geth::{CallFrame, CallLogFrame, GethTrace, TraceResult};
use citrea_evm::mb_to_bytes;
use schnellru::Limiter;

/// Upper bound on the number of cached blocks, kept alongside the byte bound so that a very large
/// number of very small entries cannot grow the map's own table without limit.
const MAX_TRACE_BLOCKS: usize = 1000;

/// Bounds an LRU map of block traces by their estimated heap size instead of by entry count.
pub(crate) struct ByTraceSize {
    max_bytes: usize,
    used: usize,
}

impl ByTraceSize {
    pub(crate) const fn new(max_bytes: usize) -> Self {
        Self { max_bytes, used: 0 }
    }

    /// Builds a limiter from a megabyte budget via [`mb_to_bytes`], which clamps so an overflowing
    /// or absurd configuration cannot wrap the byte computation into a bogus (possibly unbounded)
    /// limit.
    pub(crate) fn from_mb(mb: u64) -> Self {
        Self::new(mb_to_bytes(mb))
    }
}

impl Limiter<u64, Vec<TraceResult>> for ByTraceSize {
    type KeyToInsert<'a> = u64;
    type LinkType = u32;

    fn is_over_the_limit(&self, length: usize) -> bool {
        self.used > self.max_bytes || length > MAX_TRACE_BLOCKS
    }

    fn on_insert(
        &mut self,
        _length: usize,
        key: u64,
        value: Vec<TraceResult>,
    ) -> Option<(u64, Vec<TraceResult>)> {
        let size = traces_size(&value);
        // An entry larger than the whole budget cannot fit even in an empty map. Returning `Some`
        // here would let schnellru account it, see the map is over the limit, and then pop every
        // entry (this one included) trying to get back under - flushing the whole cache for a
        // single oversized block. Returning `None` rejects just this entry and leaves the rest.
        if size > self.max_bytes {
            return None;
        }
        self.used = self.used.saturating_add(size);
        Some((key, value))
    }

    fn on_replace(
        &mut self,
        _length: usize,
        _old_key: &mut u64,
        _new_key: u64,
        old_value: &mut Vec<TraceResult>,
        new_value: &mut Vec<TraceResult>,
    ) -> bool {
        let new_size = traces_size(new_value);
        // A replacement larger than the whole budget can never fit, exactly as in `on_insert`.
        // Returning `true` would account the oversized value and then make schnellru pop every
        // entry trying to get back under the limit, flushing the cache for one oversized block.
        // Returning `false` drops only the old entry (its bytes are reclaimed in `on_removed`) and
        // rejects the replacement, leaving the rest of the cache intact.
        if new_size > self.max_bytes {
            return false;
        }
        self.used = self
            .used
            .saturating_sub(traces_size(old_value))
            .saturating_add(new_size);
        true
    }

    fn on_removed(&mut self, _key: &mut u64, value: &mut Vec<TraceResult>) {
        self.used = self.used.saturating_sub(traces_size(value));
    }

    fn on_cleared(&mut self) {
        self.used = 0;
    }

    fn on_grow(&mut self, _new_memory_usage: usize) -> bool {
        true
    }
}

/// Estimated bytes retained by one block's traces.
///
/// Only the call tracer is measured in detail, because that is the only tracer whose output is
/// cached (see `create_trace_cache_opts`). Should that ever change, the other variants are counted
/// as their shallow size, which would under-report.
fn traces_size(traces: &[TraceResult]) -> usize {
    traces
        .iter()
        .map(|trace| {
            let inner = match trace {
                TraceResult::Success {
                    result: GethTrace::CallTracer(frame),
                    ..
                } => call_frame_size(frame),
                TraceResult::Success { .. } => 0,
                TraceResult::Error { error, .. } => error.len(),
            };
            std::mem::size_of::<TraceResult>() + inner
        })
        .sum()
}

fn call_frame_size(frame: &CallFrame) -> usize {
    std::mem::size_of::<CallFrame>()
        + frame.input.len()
        + frame.output.as_ref().map_or(0, |output| output.len())
        + frame.error.as_ref().map_or(0, |error| error.len())
        + frame
            .revert_reason
            .as_ref()
            .map_or(0, |reason| reason.len())
        + frame.typ.len()
        + frame.logs.iter().map(call_log_size).sum::<usize>()
        + frame.calls.iter().map(call_frame_size).sum::<usize>()
}

fn call_log_size(log: &CallLogFrame) -> usize {
    std::mem::size_of::<CallLogFrame>()
        + log.data.as_ref().map_or(0, |data| data.len())
        + log.topics.as_ref().map_or(0, |topics| {
            topics.len() * std::mem::size_of::<alloy_primitives::B256>()
        })
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;
    use schnellru::LruMap;

    #[test]
    fn cache_limit_is_clamped_and_never_overflows() {
        // A normal value converts straight to bytes.
        assert_eq!(
            super::ByTraceSize::from_mb(512).max_bytes,
            512 * 1024 * 1024
        );
        // An overflowing / absurd value is clamped to 1 TiB, not wrapped or panicking.
        assert_eq!(
            super::ByTraceSize::from_mb(u64::MAX).max_bytes,
            (1usize << 20) * 1024 * 1024
        );
    }

    use super::*;

    /// One block's traces, `payload` bytes of call data spread over two nested frames.
    fn traces(payload: usize) -> Vec<TraceResult> {
        let child = CallFrame {
            input: Bytes::from(vec![0u8; payload / 2]),
            ..Default::default()
        };
        let root = CallFrame {
            input: Bytes::from(vec![0u8; payload / 2]),
            calls: vec![child],
            ..Default::default()
        };
        vec![TraceResult::Success {
            result: GethTrace::CallTracer(root),
            tx_hash: None,
        }]
    }

    #[test]
    fn evicts_by_bytes_not_by_entry_count() {
        let mut cache = LruMap::new(ByTraceSize::new(4 * 1024 * 1024));

        // eight entries of 1MB each: the byte bound has to evict even though the entry count is
        // nowhere near the 1000 entry cap
        for block in 0..8u64 {
            cache.insert(block, traces(1024 * 1024));
        }
        assert!(
            cache.len() < 8,
            "expected eviction under a 4MB budget, {} entries survived",
            cache.len()
        );

        // small entries are not evicted for the same count
        let mut cache = LruMap::new(ByTraceSize::new(4 * 1024 * 1024));
        for block in 0..8u64 {
            cache.insert(block, traces(64));
        }
        assert_eq!(cache.len(), 8);
    }

    #[test]
    fn nested_call_data_is_counted() {
        assert!(traces_size(&traces(8192)) > 8192);
    }

    /// A block whose traces are larger than the whole budget must be rejected on its own, without
    /// evicting the entries already cached. Returning `Some` from `on_insert` for such an entry
    /// made schnellru pop everything trying to get back under the limit, flushing the cache.
    #[test]
    fn oversized_entry_does_not_flush_the_cache() {
        let mut cache = LruMap::new(ByTraceSize::new(4 * 1024 * 1024));

        // three small entries that fit comfortably under the 4MB budget
        for block in 0..3u64 {
            cache.insert(block, traces(64));
        }
        assert_eq!(cache.len(), 3);

        // one block larger than the whole budget: it is rejected, not accepted-then-evicted
        let inserted = cache.insert(99, traces(8 * 1024 * 1024));
        assert!(
            !inserted,
            "an entry larger than the budget should be rejected"
        );

        // the oversized block is absent and the small entries all survive
        assert!(
            cache.peek(&99).is_none(),
            "the oversized block must not be cached"
        );
        assert_eq!(cache.len(), 3, "existing entries must not be evicted");
        for block in 0..3u64 {
            assert!(
                cache.peek(&block).is_some(),
                "block {block} should still be cached"
            );
        }
    }

    /// Replacing an existing block with traces larger than the whole budget must reject the
    /// replacement and drop only that one key, never evict the rest of the cache. Returning `true`
    /// from `on_replace` for such an entry let schnellru account it and then pop everything trying
    /// to get back under the limit - the same flush `on_insert` already guards against.
    #[test]
    fn oversized_replacement_does_not_flush_the_cache() {
        let mut cache = LruMap::new(ByTraceSize::new(4 * 1024 * 1024));

        // four small entries that fit comfortably under the 4MB budget
        for block in 0..4u64 {
            cache.insert(block, traces(64));
        }
        assert_eq!(cache.len(), 4);

        // replace block 0 with traces larger than the whole budget: rejected, and only block 0 is
        // dropped (schnellru removes the old entry when `on_replace` returns false).
        let inserted = cache.insert(0, traces(8 * 1024 * 1024));
        assert!(!inserted, "an oversized replacement should be rejected");
        assert!(
            cache.peek(&0).is_none(),
            "the oversized replacement must not be cached"
        );

        // the other three entries all survive
        assert_eq!(cache.len(), 3, "only the replaced key should be gone");
        for block in 1..4u64 {
            assert!(
                cache.peek(&block).is_some(),
                "block {block} should still be cached"
            );
        }
    }
}
