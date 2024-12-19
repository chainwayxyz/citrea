use std::collections::VecDeque;

use alloy_primitives::TxKind;
use alloy_rpc_types_eth::transaction::{TransactionInput, TransactionRequest};
use citrea_evm::system_contracts::BridgeWrapper;
use citrea_evm::SYSTEM_SIGNER;
use tracing::instrument;

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
            from: Some(SYSTEM_SIGNER),
            to: Some(TxKind::Call(BridgeWrapper::address())),
            input: TransactionInput::new(BridgeWrapper::deposit(deposit_tx_data)),
            ..Default::default()
        }
    }

    // Given the fact that sys txs are included in the block gas limit, we should be careful to not to block other transactions
    // + a sys tx should not fail here, so we also want to limit it to not to fail any sys tx at the beginning of the block
    // (i.e. if you have 500 dep tx, due to gas, they may not be included, so it panics - we don't want that)

    // Considering the deposit amounts to be allowed, and the block count, a limit per block is convenient
    pub fn fetch_deposits(&mut self, limit_per_block: usize) -> Vec<Vec<u8>> {
        let number_of_deposits = self.accepted_deposit_txs.len().min(limit_per_block);
        self.accepted_deposit_txs
            .drain(..number_of_deposits)
            .collect()
    }

    #[instrument(level = "trace", skip_all, ret)]
    pub fn add_deposit_tx(&mut self, req: Vec<u8>) {
        self.accepted_deposit_txs.push_back(req);
    }
}
