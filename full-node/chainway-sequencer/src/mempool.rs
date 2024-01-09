use std::collections::VecDeque;

use sov_evm::RlpEvmTransaction;

pub struct Mempool {
    pub pool: VecDeque<RlpEvmTransaction>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            pool: VecDeque::new(),
        }
    }
}
