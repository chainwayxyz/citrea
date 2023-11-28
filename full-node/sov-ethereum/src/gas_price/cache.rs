use std::{
    collections::BTreeMap,
    sync::{atomic::AtomicU64, Mutex},
};

use reth_primitives::{SealedBlock, H256, U256};
use reth_rpc_types::{Block, BlockTransactions, Rich, TransactionReceipt};
use schnellru::{ByLength, LruMap};
use sov_evm::EthResult;
use sov_modules_api::WorkingSet;

use super::gas_oracle::convert_u256_to_u64;

/// Cache for gas oracle
pub struct BlockCache<C: sov_modules_api::Context> {
    // Number -> hash mapping
    number_to_hash: Mutex<LruMap<u64, H256, ByLength>>,
    cache: Mutex<LruMap<H256, Rich<Block>, ByLength>>,
    provider: sov_evm::Evm<C>,
}

impl<C: sov_modules_api::Context> BlockCache<C> {
    pub fn new(max_size: u32, provider: sov_evm::Evm<C>) -> Self {
        Self {
            number_to_hash: Mutex::new(LruMap::new(ByLength::new(max_size))),
            cache: Mutex::new(LruMap::new(ByLength::new(max_size))),
            provider,
        }
    }

    /// Gets block from cache or from provider
    pub fn get_block(
        &self,
        block_hash: H256,
        working_set: &mut WorkingSet<C>,
    ) -> EthResult<Option<Rich<Block>>> {
        // Check if block is in cache
        let mut cache = self.cache.lock().unwrap();
        let mut number_to_hash = self.number_to_hash.lock().unwrap();
        if let Some(block) = cache.get(&block_hash) {
            return Ok(Some(block.clone()));
        }

        // Get block from provider
        let block = self
            .provider
            .get_block_by_hash(block_hash, Some(true), working_set)
            .unwrap_or(None);

        // Add block to cache if it exists
        if let Some(block) = &block {
            let number =
                convert_u256_to_u64(block.header.number.unwrap_or_default()).unwrap_or_default();

            number_to_hash.insert(number, block_hash);
            cache.insert(block_hash, block.clone());
        }

        Ok(block)
    }

    /// Gets block from cache or from provider by block number
    pub fn get_block_by_number(
        &self,
        block_number: u64,
        working_set: &mut WorkingSet<C>,
    ) -> EthResult<Option<Rich<Block>>> {
        // Check if block is in cache
        if let Some(block_hash) = self.number_to_hash.lock().unwrap().get(&block_number) {
            // This immediately drops the mutex before calling get_block
            return self.get_block(*block_hash, working_set);
        }

        // block_number to hex string
        let block_number = U256::from(block_number).to_string();

        // Get block from provider
        let block = self
            .provider
            .get_block_by_number(Some(block_number), Some(true), working_set)
            .unwrap_or(None);

        // Add block to cache if it exists
        if let Some(block) = &block {
            let number =
                convert_u256_to_u64(block.header.number.unwrap_or_default()).unwrap_or_default();
            let hash = block.header.hash.unwrap_or_default();

            let mut number_to_hash = self.number_to_hash.lock().unwrap();
            number_to_hash.insert(number, hash);

            let mut cache = self.cache.lock().unwrap();
            cache.insert(hash, block.clone());
        }

        Ok(block)
    }

    pub fn get_block_with_receipts(
        &self,
        block_number: u64,
        working_set: &mut WorkingSet<C>,
    ) -> EthResult<Option<(Rich<Block>, Vec<TransactionReceipt>)>> {
        // if height not in cache, get hash from provider and call get_block
        let block = self.get_block_by_number(block_number, working_set)?;
        if let Some(block) = block {
            let receipts: Vec<TransactionReceipt> = match &block.transactions {
                BlockTransactions::Full(transactions) => {
                    transactions
                        .iter()
                        .map(|tx| {
                            self.provider
                                .get_transaction_receipt(tx.hash, working_set)
                                .unwrap()
                                .unwrap() // There is no way to get None here
                        })
                        .collect()
                }
                _ => unreachable!(),
            };

            return Ok(Some((block, receipts)));
        }

        Ok(None)
    }

    pub fn get_transactions_and_receipts(
        &self,
        block_hash: H256,
        working_set: &mut WorkingSet<C>,
    ) -> EthResult<
        Option<(
            Vec<reth_rpc_types::Transaction>,
            Vec<reth_rpc_types::TransactionReceipt>,
        )>,
    > {
        // Check if block is in cache
        let mut cache = self.cache.lock().unwrap();
        if let Some(block) = cache.get(&block_hash) {
            let (transactions, receipts) =
                self.extract_transactions_and_receipts(block, working_set)?;
            return Ok(Some((transactions, receipts)));
        }

        // Get block from provider
        let block = self
            .provider
            .get_block_by_hash(block_hash, Some(true), working_set)
            .unwrap_or(None);

        // Add block to cache if it exists
        if let Some(block) = &block {
            cache.insert(block_hash, block.clone());
        }

        if let Some(block) = block {
            let (transactions, receipts) =
                self.extract_transactions_and_receipts(&block, working_set)?;
            return Ok(Some((transactions, receipts)));
        }

        Ok(None)
    }

    fn extract_transactions_and_receipts(
        &self,
        block: &Rich<Block>,
        working_set: &mut WorkingSet<C>,
    ) -> EthResult<(
        Vec<reth_rpc_types::Transaction>,
        Vec<reth_rpc_types::TransactionReceipt>,
    )> {
        // block.transactions is enum but we know it's always Full

        let transactions: Vec<reth_rpc_types::Transaction> = match block.transactions.clone() {
            reth_rpc_types::BlockTransactions::Full(transactions) => transactions,
            _ => unreachable!(),
        };

        let receipts: Vec<TransactionReceipt> = transactions
            .iter()
            .map(|tx| {
                self.provider
                    .get_transaction_receipt(tx.hash, working_set)
                    .unwrap()
                    .unwrap() // There is no way to get None here
            })
            .collect();

        Ok((transactions, receipts))
    }
}
