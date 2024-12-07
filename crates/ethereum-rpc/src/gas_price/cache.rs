use reth_primitives::{BlockNumberOrTag, B256};
use reth_rpc_eth_types::EthResult;
use reth_rpc_types::{AnyTransactionReceipt, Block, BlockTransactions, Rich};
use schnellru::{ByLength, LruMap};
use sov_modules_api::WorkingSet;

/// Cache for gas oracle
pub struct BlockCache<C: sov_modules_api::Context> {
    number_to_hash: LruMap<u64, B256, ByLength>, // Number -> hash mapping
    cache: LruMap<B256, Rich<Block>, ByLength>,
    provider: citrea_evm::Evm<C>,
}

impl<C: sov_modules_api::Context> BlockCache<C> {
    pub fn new(max_size: u32, provider: citrea_evm::Evm<C>) -> Self {
        Self {
            number_to_hash: LruMap::new(ByLength::new(max_size)),
            cache: LruMap::new(ByLength::new(max_size)),
            provider,
        }
    }

    /// Gets block from cache or from provider
    #[allow(unused)]
    pub fn get_block(
        &mut self,
        block_hash: B256,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> EthResult<Option<Rich<Block>>> {
        // Check if block is in cache
        if let Some(block) = self.cache.get(&block_hash) {
            // Even though block is in cache, ask number_to_hash to keep it in sync
            let number: u64 = block.header.number.unwrap_or_default();
            self.number_to_hash.get(&number);
            return Ok(Some(block.clone()));
        }

        // Get block from provider
        let block = self
            .provider
            .get_block_by_hash(block_hash, Some(true), working_set)
            .unwrap_or(None);

        // Add block to cache if it exists
        if let Some(block) = &block {
            let number: u64 = block.header.number.unwrap_or_default();

            self.number_to_hash.insert(number, block_hash);
            self.cache.insert(block_hash, block.clone());
        }

        Ok(block)
    }

    /// Gets block from cache or from provider by block number
    pub fn get_block_by_number(
        &mut self,
        block_number: u64,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> EthResult<Option<Rich<Block>>> {
        // Check if block is in cache
        if let Some(block_hash) = self.number_to_hash.get(&block_number) {
            return Ok(Some(self.cache.get(block_hash).unwrap().clone()));
        }

        // Get block from provider
        let block = self
            .provider
            .get_block_by_number(
                Some(BlockNumberOrTag::Number(block_number)),
                Some(true),
                working_set,
            )
            .unwrap_or(None);

        // Add block to cache if it exists
        if let Some(block) = &block {
            let number: u64 = block.header.number.unwrap_or_default();
            let hash = block.header.hash.unwrap_or_default();

            self.number_to_hash.insert(number, hash);
            self.cache.insert(hash, block.clone());
        }

        Ok(block)
    }

    pub fn get_block_with_receipts(
        &mut self,
        block_number: u64,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> EthResult<Option<(Rich<Block>, Vec<AnyTransactionReceipt>)>> {
        // if height not in cache, get hash from provider and call get_block
        let block = self.get_block_by_number(block_number, working_set)?;
        if let Some(block) = block {
            // Receipts are not added to cache but their fee history will be kept in cache in fee_history.rs
            let receipts: Vec<_> = match &block.transactions {
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
