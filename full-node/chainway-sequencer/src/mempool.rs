use std::collections::VecDeque;

use sov_evm::RlpEvmTransaction;

pub struct Mempool {
    pub pool: VecDeque<RlpEvmTransaction>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            pool: VecDeque::new(),
        }
    }
}
