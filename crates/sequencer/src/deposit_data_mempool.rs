use std::collections::VecDeque;

use citrea_evm::system_contracts::Bridge;
use reth_primitives::{self, address};
use reth_rpc_types::{TransactionInput, TransactionRequest};
use sov_rollup_interface::rpc::HexTx;

#[derive(Clone, Debug)]
pub struct DepositDataMempool {
    accepted_deposit_txs: VecDeque<HexTx>,
    limit_per_block: usize,
}

impl DepositDataMempool {
    pub fn new(limit_per_block: usize) -> Self {
        Self {
            accepted_deposit_txs: VecDeque::new(),
            limit_per_block,
        }
    }

    pub fn make_deposit_tx_from_data(&mut self, deposit_tx_data: HexTx) -> TransactionRequest {
        TransactionRequest {
            from: Some(address!("deaddeaddeaddeaddeaddeaddeaddeaddeaddead")),
            to: Some(Bridge::address()),
            input: TransactionInput::new(Bridge::deposit(deposit_tx_data.tx)),
            ..Default::default()
        }
    }

    pub fn fetch_deposits(&mut self) -> Vec<Vec<u8>> {
        let mut deposits = Vec::new();
        for _ in 0..self.limit_per_block {
            if let Some(deposit) = self.accepted_deposit_txs.pop_front() {
                deposits.push(deposit.tx);
            } else {
                break;
            }
        }
        deposits
    }

    pub fn add_deposit_tx(&mut self, req: HexTx) {
        self.accepted_deposit_txs.push_back(req);
    }
}
