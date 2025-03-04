// Until we transition to the new system completely, we name old/new
mod accessors;
pub mod new;
pub mod old;
pub mod primitives;

// L2 activation height of the fork, and the batch proof method ID
type InitialBatchProofMethodIds = Vec<(u64, [u32; 8])>;
