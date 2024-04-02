use citrea_evm::{Evm, EvmChainConfig};
use reth_db::models::StoredBlockBodyIndices;
use reth_interfaces::provider::ProviderResult;
use reth_primitives::{
    Account, Address, BlockNumberOrTag, Bytecode, SealedHeader, StorageKey, StorageValue, B256,
    U256,
};
use reth_provider::{
    AccountReader, BlockHashReader, BlockIdReader, BlockNumReader, BlockReader, BlockReaderIdExt,
    ChainSpecProvider, HeaderProvider, ReceiptProvider, ReceiptProviderIdExt, StateProvider,
    StateProviderFactory, StateRootProvider, TransactionsProvider, WithdrawalsProvider,
};
use reth_rpc_types::{Block, BlockTransactions};
use reth_trie::updates::TrieUpdates;
use revm::db::states::bundle_state::BundleState;
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
        self.evm.get_chain_config(&mut working_set)
    }

    pub fn last_block_tx_hashes(&self) -> Vec<B256> {
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());
        let rich_block = self
            .evm
            .get_block_by_number(None, None, &mut working_set)
            .unwrap()
            .unwrap();
        match rich_block.inner.transactions {
            BlockTransactions::Hashes(hashes) => hashes,
            _ => vec![],
        }
    }

    pub fn genesis_block(&self) -> ProviderResult<Option<Block>> {
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());
        let rich_block = self
            .evm
            .get_block_by_number(Some(BlockNumberOrTag::Earliest), None, &mut working_set)
            .unwrap()
            .unwrap();
        Ok(Some(rich_block.inner))
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

impl<C: sov_modules_api::Context> BlockReaderIdExt for DbProvider<C> {
    fn block_by_id(
        &self,
        _id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("block_by_id")
    }
    fn block_by_number_or_tag(
        &self,
        _id: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("block_by_number_or_tag")
    }
    fn finalized_header(&self) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("finalized_header")
    }
    fn header_by_id(
        &self,
        _id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_id")
    }
    fn header_by_number_or_tag(
        &self,
        _id: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_number_or_tag")
    }
    fn latest_header(&self) -> ProviderResult<Option<SealedHeader>> {
        let latest_header = {
            let mut working_set = WorkingSet::<C>::new(self.storage.clone());
            Some(self.evm.last_sealed_header(&mut working_set))
        };
        Ok(latest_header)
    }
    fn ommers_by_id(
        &self,
        _id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<Vec<reth_primitives::Header>>> {
        unimplemented!("ommers_by_id")
    }
    fn ommers_by_number_or_tag(
        &self,
        _id: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<Vec<reth_primitives::Header>>> {
        unimplemented!("ommers_by_number_or_tag")
    }
    fn pending_header(&self) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("pending_header")
    }
    fn safe_header(&self) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("safe_header")
    }
    fn sealed_header_by_id(
        &self,
        _id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_header_by_id")
    }
    fn sealed_header_by_number_or_tag(
        &self,
        _id: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_header_by_number_or_tag")
    }
}

impl<C: sov_modules_api::Context> HeaderProvider for DbProvider<C> {
    fn header(
        &self,
        _block_hash: &reth_primitives::BlockHash,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header")
    }
    fn header_by_hash_or_number(
        &self,
        _hash_or_num: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_hash_or_number")
    }
    fn header_by_number(&self, _num: u64) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_number")
    }
    fn header_td(&self, _hash: &reth_primitives::BlockHash) -> ProviderResult<Option<U256>> {
        unimplemented!("header_td")
    }
    fn header_td_by_number(
        &self,
        _number: reth_primitives::BlockNumber,
    ) -> ProviderResult<Option<U256>> {
        unimplemented!("header_td_by_number")
    }
    fn headers_range(
        &self,
        _range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
    ) -> ProviderResult<Vec<reth_primitives::Header>> {
        unimplemented!("headers_range")
    }
    fn is_known(&self, _block_hash: &reth_primitives::BlockHash) -> ProviderResult<bool> {
        unimplemented!("is_known")
    }
    fn sealed_header(
        &self,
        _number: reth_primitives::BlockNumber,
    ) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_header")
    }
    fn sealed_headers_range(
        &self,
        _range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
    ) -> ProviderResult<Vec<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_headers_range")
    }
    fn sealed_headers_while(
        &self,
        _range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
        _predicate: impl FnMut(&SealedHeader) -> bool,
    ) -> reth_interfaces::provider::ProviderResult<Vec<SealedHeader>> {
        unimplemented!("sealed_headers_while")
    }
}

impl<C: sov_modules_api::Context> BlockHashReader for DbProvider<C> {
    fn block_hash(&self, _number: reth_primitives::BlockNumber) -> ProviderResult<Option<B256>> {
        unimplemented!()
    }
    fn canonical_hashes_range(
        &self,
        _start: reth_primitives::BlockNumber,
        _end: reth_primitives::BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        unimplemented!("canonical_hashes_range")
    }
    fn convert_block_hash(
        &self,
        _hash_or_number: reth_rpc_types::BlockHashOrNumber,
    ) -> ProviderResult<Option<reth_primitives::B256>> {
        unimplemented!("convert_block_hash")
    }
}

impl<C: sov_modules_api::Context> BlockNumReader for DbProvider<C> {
    fn best_block_number(&self) -> ProviderResult<reth_primitives::BlockNumber> {
        unimplemented!("best_block_number")
    }
    fn block_number(&self, _hash: B256) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!("block_number")
    }
    fn chain_info(&self) -> ProviderResult<reth_primitives::ChainInfo> {
        unimplemented!("chain_info")
    }
    fn convert_hash_or_number(
        &self,
        _id: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!("convert_hash_or_number")
    }
    fn convert_number(
        &self,
        _id: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<B256>> {
        unimplemented!("convert_number")
    }
    fn last_block_number(&self) -> ProviderResult<reth_primitives::BlockNumber> {
        unimplemented!("last_block_number")
    }
}

impl<C: sov_modules_api::Context> BlockIdReader for DbProvider<C> {
    fn block_hash_for_id(
        &self,
        _block_id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<B256>> {
        unimplemented!("block_hash_for_id")
    }
    fn block_number_for_id(
        &self,
        _block_id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!("block_number_for_id")
    }
    fn convert_block_number(
        &self,
        _num: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!("convert_block_number")
    }
    fn finalized_block_hash(&self) -> ProviderResult<Option<B256>> {
        unimplemented!("finalized_block_hash")
    }
    fn finalized_block_num_hash(&self) -> ProviderResult<Option<reth_primitives::BlockNumHash>> {
        unimplemented!("finalized_block_num_hash")
    }
    fn finalized_block_number(&self) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!("finalized_block_number")
    }
    fn pending_block_num_hash(&self) -> ProviderResult<Option<reth_primitives::BlockNumHash>> {
        unimplemented!("pending_block_num_hash")
    }
    fn safe_block_hash(&self) -> ProviderResult<Option<B256>> {
        unimplemented!("safe_block_hash")
    }
    fn safe_block_num_hash(&self) -> ProviderResult<Option<reth_primitives::BlockNumHash>> {
        unimplemented!("safe_block_num_hash")
    }
    fn safe_block_number(&self) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!("safe_block_number")
    }
}

impl<C: sov_modules_api::Context> BlockReader for DbProvider<C> {
    fn block(
        &self,
        _id: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("block")
    }
    fn block_body_indices(&self, _num: u64) -> ProviderResult<Option<StoredBlockBodyIndices>> {
        unimplemented!("block_body_indices")
    }
    fn block_by_hash(&self, _hash: B256) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("block_by_hash")
    }
    fn block_by_number(&self, _num: u64) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("block_by_number")
    }
    fn block_with_senders(
        &self,
        _id: reth_rpc_types::BlockHashOrNumber,
        _transaction_kind: reth_provider::TransactionVariant,
    ) -> ProviderResult<Option<reth_primitives::BlockWithSenders>> {
        unimplemented!("block_with_senders")
    }
    fn find_block_by_hash(
        &self,
        _hash: B256,
        _source: reth_provider::BlockSource,
    ) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("find_block_by_hash")
    }
    fn ommers(
        &self,
        _id: reth_primitives::BlockHashOrNumber,
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
        _range: std::ops::RangeInclusive<reth_primitives::BlockNumber>,
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
        _range: impl std::ops::RangeBounds<reth_primitives::TxNumber>,
    ) -> ProviderResult<Vec<Address>> {
        unimplemented!("senders_by_tx_range")
    }
    fn transaction_block(
        &self,
        _id: reth_primitives::TxNumber,
    ) -> ProviderResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!("transaction_block")
    }
    fn transaction_by_hash(
        &self,
        _hash: reth_primitives::TxHash,
    ) -> ProviderResult<Option<reth_primitives::TransactionSigned>> {
        unimplemented!("transaction_by_hash")
    }
    fn transaction_by_hash_with_meta(
        &self,
        _hash: reth_primitives::TxHash,
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
        _id: reth_primitives::TxNumber,
    ) -> ProviderResult<Option<reth_primitives::TransactionSigned>> {
        unimplemented!("transaction_by_id")
    }
    fn transaction_by_id_no_hash(
        &self,
        _id: reth_primitives::TxNumber,
    ) -> ProviderResult<Option<reth_primitives::TransactionSignedNoHash>> {
        unimplemented!("transaction_by_id_no_hash")
    }
    fn transaction_id(
        &self,
        _tx_hash: reth_primitives::TxHash,
    ) -> ProviderResult<Option<reth_primitives::TxNumber>> {
        unimplemented!("transaction_id")
    }
    fn transaction_sender(
        &self,
        _id: reth_primitives::TxNumber,
    ) -> ProviderResult<Option<Address>> {
        unimplemented!("transaction_sender")
    }
    fn transactions_by_block(
        &self,
        _block: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<reth_primitives::TransactionSigned>>> {
        unimplemented!("transactions_by_block")
    }
    fn transactions_by_block_range(
        &self,
        _range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
    ) -> ProviderResult<Vec<Vec<reth_primitives::TransactionSigned>>> {
        unimplemented!("transactions_by_block_range")
    }
    fn transactions_by_tx_range(
        &self,
        _range: impl std::ops::RangeBounds<reth_primitives::TxNumber>,
    ) -> ProviderResult<Vec<reth_primitives::TransactionSignedNoHash>> {
        unimplemented!("transactions_by_tx_range")
    }
}

impl<C: sov_modules_api::Context> ReceiptProvider for DbProvider<C> {
    fn receipt(
        &self,
        _id: reth_primitives::TxNumber,
    ) -> ProviderResult<Option<reth_primitives::Receipt>> {
        unimplemented!("receipt")
    }
    fn receipt_by_hash(
        &self,
        _hash: reth_primitives::TxHash,
    ) -> ProviderResult<Option<reth_primitives::Receipt>> {
        unimplemented!("receipt_by_hash")
    }
    fn receipts_by_block(
        &self,
        _block: reth_primitives::BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!("receipts_by_block")
    }
    fn receipts_by_tx_range(
        &self,
        _range: impl std::ops::RangeBounds<reth_primitives::TxNumber>,
    ) -> reth_interfaces::provider::ProviderResult<Vec<reth_primitives::Receipt>> {
        unimplemented!("receipts_by_tx_range")
    }
}

impl<C: sov_modules_api::Context> ReceiptProviderIdExt for DbProvider<C> {
    fn receipts_by_block_id(
        &self,
        _block: reth_primitives::BlockId,
    ) -> ProviderResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!("receipts_by_block_id")
    }
    fn receipts_by_number_or_tag(
        &self,
        _number_or_tag: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!("receipts_by_number_or_tag")
    }
}

impl<C: sov_modules_api::Context> WithdrawalsProvider for DbProvider<C> {
    fn latest_withdrawal(&self) -> ProviderResult<Option<reth_primitives::Withdrawal>> {
        unimplemented!("latest_withdrawal")
    }
    fn withdrawals_by_block(
        &self,
        _id: reth_primitives::BlockHashOrNumber,
        _timestamp: u64,
    ) -> ProviderResult<Option<reth_primitives::Withdrawals>> {
        unimplemented!("withdrawals_by_block")
    }
}

impl<C: sov_modules_api::Context> ChainSpecProvider for DbProvider<C> {
    fn chain_spec(&self) -> std::sync::Arc<reth_primitives::ChainSpec> {
        unimplemented!("chain_spec")
    }
}

impl<C: sov_modules_api::Context> StateProviderFactory for DbProvider<C> {
    fn history_by_block_hash(
        &self,
        _block: reth_primitives::BlockHash,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!("history_by_block_hash")
    }
    fn history_by_block_number(
        &self,
        _block: reth_primitives::BlockNumber,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!("history_by_block_number")
    }
    fn latest(&self) -> ProviderResult<reth_provider::StateProviderBox> {
        Ok(Box::new(self.clone()))
    }
    fn pending(&self) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!("pending")
    }
    fn pending_state_by_hash(
        &self,
        _block_hash: B256,
    ) -> ProviderResult<Option<reth_provider::StateProviderBox>> {
        unimplemented!("pending_state_by_hash")
    }
    fn pending_with_provider(
        &self,
        _post_state_data: Box<dyn reth_provider::BundleStateDataProvider>,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!("pending_with_provider")
    }
    fn state_by_block_hash(
        &self,
        _block: reth_primitives::BlockHash,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!("state_by_block_hash")
    }
    fn state_by_block_id(
        &self,
        _block_id: reth_primitives::BlockId,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!("state_by_block_id")
    }
    fn state_by_block_number_or_tag(
        &self,
        _number_or_tag: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!("state_by_block_number_or_tag")
    }
}

impl<C: sov_modules_api::Context> StateRootProvider for DbProvider<C> {
    #[doc = r" Returns the state root of the BundleState on top of the current state."]
    fn state_root(&self, _bundle_state: &BundleState) -> ProviderResult<reth_primitives::B256> {
        unimplemented!("state_root")
    }
    fn state_root_with_updates(
        &self,
        _bundle_state: &BundleState,
    ) -> reth_interfaces::provider::ProviderResult<(reth_primitives::B256, TrieUpdates)> {
        unimplemented!("state_root_with_updates")
    }
}

impl<C: sov_modules_api::Context> StateProvider for DbProvider<C> {
    fn account_balance(&self, _addr: Address) -> ProviderResult<Option<U256>> {
        unimplemented!("account_balance")
    }
    fn account_code(&self, _addr: Address) -> ProviderResult<Option<reth_primitives::Bytecode>> {
        unimplemented!("account_code")
    }

    fn storage(
        &self,
        _account: Address,
        _storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        unimplemented!("storage")
    }

    fn bytecode_by_hash(
        &self,
        _code_hash: reth_primitives::B256,
    ) -> ProviderResult<Option<Bytecode>> {
        unimplemented!("bytecode_by_hash")
    }

    fn proof(
        &self,
        _address: Address,
        _keys: &[reth_primitives::B256],
    ) -> ProviderResult<reth_primitives::trie::AccountProof> {
        unimplemented!("proof")
    }
    fn account_nonce(&self, _addr: Address) -> ProviderResult<Option<u64>> {
        unimplemented!("account_nonce")
    }
}
