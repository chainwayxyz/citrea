use reth_db::models::StoredBlockBodyIndices;
use reth_interfaces::{provider::ProviderResult, RethError, RethResult};
use reth_primitives::{
    Account, Address, BlockNumberOrTag, Bytecode, Bytes, Header, SealedHeader, StorageKey,
    StorageValue, B256, H256, U256,
};
use reth_provider::{
    AccountReader, BlockHashReader, BlockIdReader, BlockNumReader, BlockReader, BlockReaderIdExt,
    BundleStateWithReceipts, ChainSpecProvider, HeaderProvider, ReceiptProvider,
    ReceiptProviderIdExt, StateProvider, StateProviderFactory, StateRootProvider,
    TransactionsProvider, WithdrawalsProvider,
};
use reth_rpc_types::{Block, BlockTransactions, Header as RpcHeader};
use reth_trie::updates::TrieUpdates;
use sov_evm::{Evm, EvmChainConfig};
use sov_modules_api::WorkingSet;

#[derive(Clone)]
pub struct DbProvider<C: sov_modules_api::Context> {
    pub evm: Evm<C>,
    pub storage: C::Storage,
}

impl<C: sov_modules_api::Context> DbProvider<C> {
    pub fn new(storage: C::Storage) -> Self {
        let evm = Evm::<C>::default();
        Self { evm, storage }
    }

    pub fn cfg(&self) -> EvmChainConfig {
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());
        self.evm.get_config(&mut working_set)
    }

    pub fn latest_block_tx_hashes(&self) -> ProviderResult<Option<Vec<H256>>> {
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());
        let r_block = self
            .evm
            .get_block_by_number(None, None, &mut working_set)
            .unwrap()
            .unwrap();
        match r_block.inner.transactions {
            BlockTransactions::Hashes(hashes) => Ok(Some(hashes)),
            _ => Ok(None),
        }
    }

    pub fn genesis_block(&self) -> ProviderResult<Option<Block>> {
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());
        let r_block = self
            .evm
            .get_block_by_number(Some(BlockNumberOrTag::Earliest), None, &mut working_set)
            .unwrap()
            .unwrap();
        Ok(Some(r_block.inner))
    }
}

impl<C: sov_modules_api::Context> BlockReaderIdExt for DbProvider<C> {
    fn block_by_id(
        &self,
        id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!()
    }
    fn block_by_number_or_tag(
        &self,
        id: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!()
    }
    fn finalized_header(&self) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!()
    }
    fn header_by_id(
        &self,
        id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!()
    }
    fn header_by_number_or_tag(
        &self,
        id: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!()
    }
    fn latest_header(&self) -> ProviderResult<Option<SealedHeader>> {
        let latest_header = {
            let mut working_set = WorkingSet::<C>::new(self.storage.clone());
            Some(self.evm.latest_sealed_header(&mut working_set))
        };
        Ok(latest_header)
    }
    fn ommers_by_id(
        &self,
        id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<Vec<reth_primitives::Header>>> {
        unimplemented!()
    }
    fn ommers_by_number_or_tag(
        &self,
        id: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<Vec<reth_primitives::Header>>> {
        unimplemented!()
    }
    fn pending_header(&self) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!()
    }
    fn safe_header(&self) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("safe_header")
    }
    fn sealed_header_by_id(
        &self,
        id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_header_by_id")
    }
    fn sealed_header_by_number_or_tag(
        &self,
        id: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_header_by_number_or_tag")
    }
}

impl<C: sov_modules_api::Context> AccountReader for DbProvider<C> {
    #[doc = r" Get basic account information."]
    #[doc = r""]
    #[doc = r" Returns `None` if the account doesn't exist."]
    fn basic_account(&self, address: Address) -> ProviderResult<Option<Account>> {
        let account = {
            let mut working_set = WorkingSet::<C>::new(self.storage.clone());
            self.evm.basic_account(&address, &mut working_set)
        };
        Ok(account)
    }
}

impl<C: sov_modules_api::Context> HeaderProvider for DbProvider<C> {
    fn header(
        &self,
        block_hash: &reth_primitives::BlockHash,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header")
    }
    fn header_by_hash_or_number(
        &self,
        hash_or_num: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_hash_or_number")
    }
    fn header_by_number(&self, num: u64) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_number")
    }
    fn header_td(&self, hash: &reth_primitives::BlockHash) -> ProviderResult<Option<U256>> {
        unimplemented!("header_td")
    }
    fn header_td_by_number(
        &self,
        number: reth_primitives::BlockNumber,
    ) -> ProviderResult<Option<U256>> {
        unimplemented!("header_td_by_number")
    }
    fn headers_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
    ) -> ProviderResult<Vec<reth_primitives::Header>> {
        unimplemented!("headers_range")
    }
    fn is_known(&self, block_hash: &reth_primitives::BlockHash) -> ProviderResult<bool> {
        unimplemented!("is_known")
    }
    fn sealed_header(
        &self,
        number: reth_primitives::BlockNumber,
    ) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_header")
    }
    fn sealed_headers_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
    ) -> ProviderResult<Vec<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_headers_range")
    }
    fn sealed_headers_while(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
        predicate: impl FnMut(&SealedHeader) -> bool,
    ) -> reth_interfaces::provider::ProviderResult<Vec<SealedHeader>> {
        unimplemented!("sealed_headers_while")
    }
}

impl<C: sov_modules_api::Context> BlockHashReader for DbProvider<C> {
    fn block_hash(&self, number: reth_primitives::BlockNumber) -> ProviderResult<Option<B256>> {
        unimplemented!()
    }
    fn canonical_hashes_range(
        &self,
        start: reth_primitives::BlockNumber,
        end: reth_primitives::BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        unimplemented!()
    }
    fn convert_block_hash(
        &self,
        hash_or_number: reth_rpc_types::BlockHashOrNumber,
    ) -> ProviderResult<Option<reth_primitives::B256>> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> BlockNumReader for DbProvider<C> {
    fn best_block_number(&self) -> ProviderResult<reth_primitives::BlockNumber> {
        unimplemented!()
    }
    fn block_number(&self, hash: B256) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
    fn chain_info(&self) -> ProviderResult<reth_primitives::ChainInfo> {
        unimplemented!()
    }
    fn convert_hash_or_number(
        &self,
        id: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
    fn convert_number(
        &self,
        id: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<B256>> {
        unimplemented!()
    }
    fn last_block_number(&self) -> ProviderResult<reth_primitives::BlockNumber> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> BlockIdReader for DbProvider<C> {
    fn block_hash_for_id(
        &self,
        block_id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<B256>> {
        unimplemented!()
    }
    fn block_number_for_id(
        &self,
        block_id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
    fn convert_block_number(
        &self,
        num: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
    fn finalized_block_hash(&self) -> ProviderResult<Option<B256>> {
        unimplemented!()
    }
    fn finalized_block_num_hash(&self) -> ProviderResult<Option<reth_primitives::BlockNumHash>> {
        unimplemented!()
    }
    fn finalized_block_number(&self) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
    fn pending_block_num_hash(&self) -> ProviderResult<Option<reth_primitives::BlockNumHash>> {
        unimplemented!()
    }
    fn safe_block_hash(&self) -> ProviderResult<Option<B256>> {
        unimplemented!()
    }
    fn safe_block_num_hash(&self) -> ProviderResult<Option<reth_primitives::BlockNumHash>> {
        unimplemented!()
    }
    fn safe_block_number(&self) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> BlockReader for DbProvider<C> {
    fn block(
        &self,
        id: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("block")
    }
    fn block_body_indices(&self, num: u64) -> ProviderResult<Option<StoredBlockBodyIndices>> {
        unimplemented!("block_body_indices")
    }
    fn block_by_hash(&self, hash: B256) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("block_by_hash")
    }
    fn block_by_number(&self, num: u64) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("block_by_number")
    }
    fn block_with_senders(
        &self,
        id: reth_rpc_types::BlockHashOrNumber,
        transaction_kind: reth_provider::TransactionVariant,
    ) -> ProviderResult<Option<reth_primitives::BlockWithSenders>> {
        unimplemented!("block_with_senders")
    }
    fn find_block_by_hash(
        &self,
        hash: B256,
        source: reth_provider::BlockSource,
    ) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("find_block_by_hash")
    }
    fn ommers(
        &self,
        id: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<reth_primitives::Header>>> {
        unimplemented!("ommers")
    }
    fn pending_block(&self) -> ProviderResult<Option<reth_primitives::SealedBlock>> {
        unimplemented!("pending_block")
    }
    fn pending_block_and_receipts(
        &self,
    ) -> ProviderResult<Option<(reth_primitives::SealedBlock, Vec<reth_primitives::Receipt>)>> {
        unimplemented!("pending_block_and_receipts")
    }
    fn block_range(
        &self,
        range: std::ops::RangeInclusive<reth_primitives::BlockNumber>,
    ) -> reth_interfaces::provider::ProviderResult<Vec<reth_primitives::Block>> {
        unimplemented!("block_range")
    }
    fn pending_block_with_senders(
        &self,
    ) -> reth_interfaces::provider::ProviderResult<Option<reth_primitives::SealedBlockWithSenders>>
    {
        unimplemented!("pending_block_with_senders")
    }
}

impl<C: sov_modules_api::Context> TransactionsProvider for DbProvider<C> {
    fn senders_by_tx_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::TxNumber>,
    ) -> ProviderResult<Vec<Address>> {
        unimplemented!("senders_by_tx_range")
    }
    fn transaction_block(
        &self,
        id: reth_primitives::TxNumber,
    ) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!("transaction_block")
    }
    fn transaction_by_hash(
        &self,
        hash: reth_primitives::TxHash,
    ) -> ProviderResult<Option<reth_primitives::TransactionSigned>> {
        unimplemented!("transaction_by_hash")
    }
    fn transaction_by_hash_with_meta(
        &self,
        hash: reth_primitives::TxHash,
    ) -> ProviderResult<
        Option<(
            reth_primitives::TransactionSigned,
            reth_primitives::TransactionMeta,
        )>,
    > {
        unimplemented!("transaction_by_hash_with_meta")
    }
    fn transaction_by_id(
        &self,
        id: reth_primitives::TxNumber,
    ) -> ProviderResult<Option<reth_primitives::TransactionSigned>> {
        unimplemented!("transaction_by_id")
    }
    fn transaction_by_id_no_hash(
        &self,
        id: reth_primitives::TxNumber,
    ) -> ProviderResult<Option<reth_primitives::TransactionSignedNoHash>> {
        unimplemented!("transaction_by_id_no_hash")
    }
    fn transaction_id(
        &self,
        tx_hash: reth_primitives::TxHash,
    ) -> ProviderResult<Option<reth_primitives::TxNumber>> {
        unimplemented!("transaction_id")
    }
    fn transaction_sender(&self, id: reth_primitives::TxNumber) -> ProviderResult<Option<Address>> {
        unimplemented!("transaction_sender")
    }
    fn transactions_by_block(
        &self,
        block: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<reth_primitives::TransactionSigned>>> {
        unimplemented!("transactions_by_block")
    }
    fn transactions_by_block_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
    ) -> ProviderResult<Vec<Vec<reth_primitives::TransactionSigned>>> {
        unimplemented!("transactions_by_block_range")
    }
    fn transactions_by_tx_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::TxNumber>,
    ) -> ProviderResult<Vec<reth_primitives::TransactionSignedNoHash>> {
        unimplemented!("transactions_by_tx_range")
    }
}

impl<C: sov_modules_api::Context> ReceiptProvider for DbProvider<C> {
    fn receipt(
        &self,
        id: reth_primitives::TxNumber,
    ) -> ProviderResult<Option<reth_primitives::Receipt>> {
        unimplemented!("receipt")
    }
    fn receipt_by_hash(
        &self,
        hash: reth_primitives::TxHash,
    ) -> ProviderResult<Option<reth_primitives::Receipt>> {
        unimplemented!("receipt_by_hash")
    }
    fn receipts_by_block(
        &self,
        block: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!("receipts_by_block")
    }
    fn receipts_by_tx_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::TxNumber>,
    ) -> reth_interfaces::provider::ProviderResult<Vec<reth_primitives::Receipt>> {
        unimplemented!("receipts_by_tx_range")
    }
}

impl<C: sov_modules_api::Context> ReceiptProviderIdExt for DbProvider<C> {
    fn receipts_by_block_id(
        &self,
        block: reth_primitives::BlockId,
    ) -> ProviderResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!()
    }
    fn receipts_by_number_or_tag(
        &self,
        number_or_tag: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> WithdrawalsProvider for DbProvider<C> {
    fn latest_withdrawal(&self) -> ProviderResult<Option<reth_primitives::Withdrawal>> {
        unimplemented!("latest_withdrawal")
    }
    fn withdrawals_by_block(
        &self,
        id: reth_primitives::BlockHashOrNumber,
        timestamp: u64,
    ) -> ProviderResult<Option<Vec<reth_primitives::Withdrawal>>> {
        unimplemented!("withdrawals_by_block")
    }
}

impl<C: sov_modules_api::Context> ChainSpecProvider for DbProvider<C> {
    fn chain_spec(&self) -> std::sync::Arc<reth_primitives::ChainSpec> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> StateProviderFactory for DbProvider<C> {
    fn history_by_block_hash(
        &self,
        block: reth_primitives::BlockHash,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!()
    }
    fn history_by_block_number(
        &self,
        block: reth_primitives::BlockNumber,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!()
    }
    // fn latest(&self) -> ProviderResult<reth_provider::StateProviderBox> {
    //     Ok(Box::new(self))
    // }
    fn latest(&self) -> ProviderResult<reth_provider::StateProviderBox> {
        Ok(Box::new(self.clone()))
    }
    fn pending(&self) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!()
    }
    fn pending_state_by_hash(
        &self,
        block_hash: B256,
    ) -> ProviderResult<Option<reth_provider::StateProviderBox>> {
        unimplemented!()
    }
    fn pending_with_provider(
        &self,
        post_state_data: Box<dyn reth_provider::BundleStateDataProvider>,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!()
    }
    fn state_by_block_hash(
        &self,
        block: reth_primitives::BlockHash,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!()
    }
    fn state_by_block_id(
        &self,
        block_id: reth_primitives::BlockId,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!()
    }
    fn state_by_block_number_or_tag(
        &self,
        number_or_tag: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> StateRootProvider for DbProvider<C> {
    #[doc = r" Returns the state root of the BundleState on top of the current state."]
    fn state_root(
        &self,
        bundle_state: &BundleStateWithReceipts,
    ) -> ProviderResult<reth_primitives::B256> {
        unimplemented!("state_root")
    }
    fn state_root_with_updates(
        &self,
        bundle_state: &BundleStateWithReceipts,
    ) -> reth_interfaces::provider::ProviderResult<(reth_primitives::B256, TrieUpdates)> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> StateProvider for DbProvider<C> {
    fn account_balance(&self, addr: Address) -> ProviderResult<Option<U256>> {
        unimplemented!("account_balance")
    }
    fn account_code(&self, addr: Address) -> ProviderResult<Option<reth_primitives::Bytecode>> {
        unimplemented!("account_code")
    }

    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        unimplemented!("storage")
    }

    fn bytecode_by_hash(
        &self,
        code_hash: reth_primitives::B256,
    ) -> ProviderResult<Option<Bytecode>> {
        unimplemented!("bytecode_by_hash")
    }

    fn proof(
        &self,
        address: Address,
        keys: &[reth_primitives::B256],
    ) -> ProviderResult<reth_primitives::trie::AccountProof> {
        unimplemented!("proof")
    }
    fn account_nonce(&self, addr: Address) -> ProviderResult<Option<u64>> {
        unimplemented!("account_nonce")
    }
}
