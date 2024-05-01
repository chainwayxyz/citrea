use std::collections::VecDeque;

use citrea_evm::system_contracts::Bridge;
use reth_primitives::{self, address};
use reth_rpc_types::{TransactionInput, TransactionRequest};

#[derive(Clone, Debug)]
pub struct DepositDataMempool {
    accepted_deposit_txs: VecDeque<Vec<u8>>,
}

impl DepositDataMempool {
    pub fn new() -> Self {
        Self {
            accepted_deposit_txs: VecDeque::new(),
        }
    }

    pub fn make_deposit_tx_from_data(&mut self, deposit_tx_data: Vec<u8>) -> TransactionRequest {
        TransactionRequest {
            from: Some(address!("deaddeaddeaddeaddeaddeaddeaddeaddeaddead")),
            to: Some(Bridge::address()),
            input: TransactionInput::new(Bridge::deposit(deposit_tx_data)),
            ..Default::default()
        }
    }

    pub fn fetch_deposits(&mut self, limit_per_block: usize) -> Vec<Vec<u8>> {
        let mut deposits = Vec::new();
        for _ in 0..limit_per_block {
            if let Some(deposit) = self.accepted_deposit_txs.pop_front() {
                deposits.push(deposit);
            } else {
                break;
            }
        }
        deposits
    }

    pub fn add_deposit_tx(&mut self, req: Vec<u8>) {
        self.accepted_deposit_txs.push_back(req);
    }
}
