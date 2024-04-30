use std::collections::VecDeque;
use std::str::FromStr;

use citrea_evm::system_contracts::Bridge;
use ethers::types::{Bytes, Eip1559TransactionRequest, H160};
use sov_rollup_interface::rpc::HexTx;

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

    pub fn _make_deposit_tx_from_data(
        &mut self,
        deposit_tx_data: HexTx,
    ) -> Eip1559TransactionRequest {
        let x: Bytes = Bytes::from(Bridge::deposit(deposit_tx_data.tx.to_vec()).to_vec());

        Eip1559TransactionRequest::new()
            .from(H160::from_str("deaddeaddeaddeaddeaddeaddeaddeaddeaddead").unwrap())
            .to(H160::from_str(&Bridge::address().to_string()).unwrap())
            .data(x)
    }

    pub fn fetch_deposists(&mut self) -> Vec<Vec<u8>> {
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

    pub fn _add_deposit_tx(&mut self, req: HexTx) {
        self.accepted_deposit_txs.push_back(req);
    }
}
