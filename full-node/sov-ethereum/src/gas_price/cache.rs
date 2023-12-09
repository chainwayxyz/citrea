use std::sync::Mutex;

use reth_primitives::{H256, U256};
use reth_rpc_types::{Block, BlockTransactions, Rich, TransactionReceipt};
use schnellru::{ByLength, LruMap};
use sov_evm::EthResult;
use sov_modules_api::WorkingSet;

use super::gas_oracle::convert_u256_to_u64;

/// Cache for gas oracle
pub struct BlockCache<C: sov_modules_api::Context> {
    // Assuming number_to_hash and cache are always in sync
    number_to_hash: Mutex<LruMap<u64, H256, ByLength>>, // Number -> hash mapping
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
            // Even though block is in cache, ask number_to_hash to keep it in sync
            let number =
                convert_u256_to_u64(block.header.number.unwrap_or_default()).unwrap_or_default();
            number_to_hash.get(&number);
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
        let mut number_to_hash = self.number_to_hash.lock().unwrap();
        let mut cache = self.cache.lock().unwrap();
        // Check if block is in cache
        if let Some(block_hash) = number_to_hash.get(&block_number) {
            return Ok(Some(cache.get(block_hash).unwrap().clone()));
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

            number_to_hash.insert(number, hash);
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
            // Receipts are not added to cache but their fee history will be kept in cache in fee_history.rs
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
}
