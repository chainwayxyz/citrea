use std::collections::VecDeque;

use alloy_primitives::TxKind;
use alloy_rpc_types_eth::transaction::{TransactionInput, TransactionRequest};
use citrea_evm::system_contracts::BridgeWrapper;
use citrea_evm::SYSTEM_SIGNER;
use tracing::instrument;

use crate::metrics::SEQUENCER_METRICS as SM;

/// A mempool specifically for handling deposit transaction data
#[derive(Clone, Debug, Default)]
pub struct DepositDataMempool {
    /// Queue of accepted deposit transaction data
    accepted_deposit_txs: VecDeque<Vec<u8>>,
}

impl DepositDataMempool {
    /// Creates a new empty deposit data mempool
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a transaction request for a deposit from raw deposit data
    ///
    /// # Arguments
    /// * `deposit_tx_data` - Raw deposit transaction data to be processed
    ///
    /// # Returns
    /// A transaction request configured for the bridge contract
    pub fn make_deposit_tx_from_data(&mut self, deposit_tx_data: Vec<u8>) -> TransactionRequest {
        TransactionRequest {
            from: Some(SYSTEM_SIGNER),
            to: Some(TxKind::Call(BridgeWrapper::address())),
            input: TransactionInput::new(BridgeWrapper::deposit(deposit_tx_data)),
            ..Default::default()
        }
    }

    /// Retrieves a limited number of deposit transactions from the mempool
    ///
    /// # Arguments
    /// * `limit_per_block` - Maximum number of deposits to return
    ///
    /// # Returns
    /// A vector of deposit transaction data, limited by the specified amount
    pub fn fetch_deposits(&mut self, limit_per_block: usize) -> Vec<Vec<u8>> {
        let number_of_deposits = self.accepted_deposit_txs.len().min(limit_per_block);
        SM.deposit_data_mempool_txs
            .set(self.accepted_deposit_txs.len() as f64);
        self.accepted_deposit_txs
            .drain(..number_of_deposits)
            .collect()
    }

    /// Adds a new deposit transaction to the mempool
    ///
    /// # Arguments
    /// * `req` - Raw deposit transaction data to be added
    #[instrument(level = "trace", skip_all, ret)]
    pub fn add_deposit_tx(&mut self, req: Vec<u8>) {
        self.accepted_deposit_txs.push_back(req);
        SM.deposit_data_mempool_txs_inc.increment(1);
        SM.deposit_data_mempool_txs
            .set(self.accepted_deposit_txs.len() as f64);
    }
}
