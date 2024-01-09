use reth_db::models::StoredBlockBodyIndices;
use reth_interfaces::{RethError, RethResult};
use reth_primitives::{
    Account, Address, BlockNumberOrTag, Bytecode, Bytes, Header, StorageKey, StorageValue, H256,
    U256,
};
use reth_provider::{
    AccountReader, BlockHashReader, BlockIdReader, BlockNumReader, BlockReader, BlockReaderIdExt,
    BundleStateWithReceipts, ChainSpecProvider, HeaderProvider, ReceiptProvider,
    ReceiptProviderIdExt, StateProvider, StateProviderFactory, StateRootProvider,
    TransactionsProvider, WithdrawalsProvider,
};
use reth_rpc_types::BlockTransactions;
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
        self.evm.cfg(&mut working_set)
    }

    pub fn latest_block_tx_hashes(&self) -> reth_interfaces::RethResult<Option<Vec<H256>>> {
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());
        let block = self.evm.latest_block(&mut working_set);
        match block.transactions {
            BlockTransactions::Hashes(hashes) => Ok(Some(hashes)),
            _ => Ok(None),
        }
        // Ok(Some(block.transactions))
    }
}

impl<C: sov_modules_api::Context> HeaderProvider for DbProvider<C> {
    fn header(
        &self,
        block_hash: &reth_primitives::BlockHash,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Header>> {
        todo!("header")
    }
    fn header_by_hash_or_number(
        &self,
        hash_or_num: reth_primitives::BlockHashOrNumber,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Header>> {
        todo!("header_by_hash_or_number")
    }
    fn header_by_number(
        &self,
        num: u64,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Header>> {
        todo!("header_by_number")
    }
    fn header_td(
        &self,
        hash: &reth_primitives::BlockHash,
    ) -> reth_interfaces::RethResult<Option<U256>> {
        todo!("header_td")
    }
    fn header_td_by_number(
        &self,
        number: reth_primitives::BlockNumber,
    ) -> reth_interfaces::RethResult<Option<U256>> {
        todo!("header_td_by_number")
    }
    fn headers_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
    ) -> reth_interfaces::RethResult<Vec<reth_primitives::Header>> {
        todo!("headers_range")
    }
    fn is_known(
        &self,
        block_hash: &reth_primitives::BlockHash,
    ) -> reth_interfaces::RethResult<bool> {
        todo!("is_known")
    }
    fn sealed_header(
        &self,
        number: reth_primitives::BlockNumber,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::SealedHeader>> {
        todo!("sealed_header")
    }
    fn sealed_headers_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
    ) -> reth_interfaces::RethResult<Vec<reth_primitives::SealedHeader>> {
        todo!("sealed_headers_range")
    }
}

impl<C: sov_modules_api::Context> BlockHashReader for DbProvider<C> {
    fn block_hash(&self, number: reth_primitives::BlockNumber) -> Result<Option<H256>, RethError> {
        unimplemented!()
    }
    fn canonical_hashes_range(
        &self,
        start: reth_primitives::BlockNumber,
        end: reth_primitives::BlockNumber,
    ) -> Result<Vec<H256>, RethError> {
        unimplemented!()
    }
    fn convert_block_hash(
        &self,
        hash_or_number: reth_primitives::BlockHashOrNumber,
    ) -> Result<Option<H256>, RethError> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> BlockNumReader for DbProvider<C> {
    fn best_block_number(&self) -> reth_interfaces::RethResult<reth_primitives::BlockNumber> {
        unimplemented!()
    }
    fn block_number(
        &self,
        hash: H256,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
    fn chain_info(&self) -> reth_interfaces::RethResult<reth_primitives::ChainInfo> {
        unimplemented!()
    }
    fn convert_hash_or_number(
        &self,
        id: reth_primitives::BlockHashOrNumber,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
    fn convert_number(
        &self,
        id: reth_primitives::BlockHashOrNumber,
    ) -> reth_interfaces::RethResult<Option<H256>> {
        unimplemented!()
    }
    fn last_block_number(&self) -> reth_interfaces::RethResult<reth_primitives::BlockNumber> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> BlockIdReader for DbProvider<C> {
    fn block_hash_for_id(
        &self,
        block_id: reth_primitives::BlockId,
    ) -> reth_interfaces::RethResult<Option<H256>> {
        unimplemented!()
    }
    fn block_number_for_id(
        &self,
        block_id: reth_primitives::BlockId,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
    fn convert_block_number(
        &self,
        num: reth_primitives::BlockNumberOrTag,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
    fn finalized_block_hash(&self) -> reth_interfaces::RethResult<Option<H256>> {
        unimplemented!()
    }
    fn finalized_block_num_hash(
        &self,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockNumHash>> {
        unimplemented!()
    }
    fn finalized_block_number(
        &self,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
    fn pending_block_num_hash(
        &self,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockNumHash>> {
        unimplemented!()
    }
    fn safe_block_hash(&self) -> reth_interfaces::RethResult<Option<H256>> {
        unimplemented!()
    }
    fn safe_block_num_hash(
        &self,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockNumHash>> {
        unimplemented!()
    }
    fn safe_block_number(
        &self,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockNumber>> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> BlockReader for DbProvider<C> {
    fn block(
        &self,
        id: reth_primitives::BlockHashOrNumber,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Block>> {
        todo!("block")
    }
    fn block_body_indices(
        &self,
        num: u64,
    ) -> reth_interfaces::RethResult<Option<StoredBlockBodyIndices>> {
        todo!("block_body_indices")
    }
    fn block_by_hash(
        &self,
        hash: H256,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Block>> {
        todo!("block_by_hash")
    }
    fn block_by_number(
        &self,
        num: u64,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Block>> {
        todo!("block_by_number")
    }
    fn block_with_senders(
        &self,
        number: reth_primitives::BlockNumber,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockWithSenders>> {
        todo!("block_with_senders")
    }
    fn find_block_by_hash(
        &self,
        hash: H256,
        source: reth_provider::BlockSource,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Block>> {
        todo!("find_block_by_hash")
    }
    fn ommers(
        &self,
        id: reth_primitives::BlockHashOrNumber,
    ) -> reth_interfaces::RethResult<Option<Vec<reth_primitives::Header>>> {
        todo!("ommers")
    }
    fn pending_block(&self) -> reth_interfaces::RethResult<Option<reth_primitives::SealedBlock>> {
        todo!("pending_block")
    }
    fn pending_block_and_receipts(
        &self,
    ) -> reth_interfaces::RethResult<
        Option<(reth_primitives::SealedBlock, Vec<reth_primitives::Receipt>)>,
    > {
        todo!("pending_block_and_receipts")
    }
}

impl<C: sov_modules_api::Context> TransactionsProvider for DbProvider<C> {
    fn senders_by_tx_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::TxNumber>,
    ) -> reth_interfaces::RethResult<Vec<Address>> {
        todo!("senders_by_tx_range")
    }
    fn transaction_block(
        &self,
        id: reth_primitives::TxNumber,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::BlockNumber>> {
        todo!("transaction_block")
    }
    fn transaction_by_hash(
        &self,
        hash: reth_primitives::TxHash,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::TransactionSigned>> {
        todo!("transaction_by_hash")
    }
    fn transaction_by_hash_with_meta(
        &self,
        hash: reth_primitives::TxHash,
    ) -> reth_interfaces::RethResult<
        Option<(
            reth_primitives::TransactionSigned,
            reth_primitives::TransactionMeta,
        )>,
    > {
        todo!("transaction_by_hash_with_meta")
    }
    fn transaction_by_id(
        &self,
        id: reth_primitives::TxNumber,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::TransactionSigned>> {
        todo!("transaction_by_id")
    }
    fn transaction_by_id_no_hash(
        &self,
        id: reth_primitives::TxNumber,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::TransactionSignedNoHash>> {
        todo!("transaction_by_id_no_hash")
    }
    fn transaction_id(
        &self,
        tx_hash: reth_primitives::TxHash,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::TxNumber>> {
        todo!("transaction_id")
    }
    fn transaction_sender(
        &self,
        id: reth_primitives::TxNumber,
    ) -> reth_interfaces::RethResult<Option<Address>> {
        todo!("transaction_sender")
    }
    fn transactions_by_block(
        &self,
        block: reth_primitives::BlockHashOrNumber,
    ) -> reth_interfaces::RethResult<Option<Vec<reth_primitives::TransactionSigned>>> {
        todo!("transactions_by_block")
    }
    fn transactions_by_block_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::BlockNumber>,
    ) -> reth_interfaces::RethResult<Vec<Vec<reth_primitives::TransactionSigned>>> {
        todo!("transactions_by_block_range")
    }
    fn transactions_by_tx_range(
        &self,
        range: impl std::ops::RangeBounds<reth_primitives::TxNumber>,
    ) -> reth_interfaces::RethResult<Vec<reth_primitives::TransactionSignedNoHash>> {
        todo!("transactions_by_tx_range")
    }
}

impl<C: sov_modules_api::Context> ReceiptProvider for DbProvider<C> {
    fn receipt(
        &self,
        id: reth_primitives::TxNumber,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Receipt>> {
        todo!("receipt")
    }
    fn receipt_by_hash(
        &self,
        hash: reth_primitives::TxHash,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Receipt>> {
        todo!("receipt_by_hash")
    }
    fn receipts_by_block(
        &self,
        block: reth_primitives::BlockHashOrNumber,
    ) -> reth_interfaces::RethResult<Option<Vec<reth_primitives::Receipt>>> {
        todo!("receipts_by_block")
    }
}

impl<C: sov_modules_api::Context> ReceiptProviderIdExt for DbProvider<C> {
    fn receipts_by_block_id(
        &self,
        block: reth_primitives::BlockId,
    ) -> reth_interfaces::RethResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!()
    }
    fn receipts_by_number_or_tag(
        &self,
        number_or_tag: reth_primitives::BlockNumberOrTag,
    ) -> reth_interfaces::RethResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> WithdrawalsProvider for DbProvider<C> {
    fn latest_withdrawal(
        &self,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Withdrawal>> {
        todo!("latest_withdrawal")
    }
    fn withdrawals_by_block(
        &self,
        id: reth_primitives::BlockHashOrNumber,
        timestamp: u64,
    ) -> reth_interfaces::RethResult<Option<Vec<reth_primitives::Withdrawal>>> {
        todo!("withdrawals_by_block")
    }
}

impl<C: sov_modules_api::Context> ChainSpecProvider for DbProvider<C> {
    fn chain_spec(&self) -> std::sync::Arc<reth_primitives::ChainSpec> {
        todo!()
    }
}

impl<C: sov_modules_api::Context> StateProviderFactory for DbProvider<C> {
    fn history_by_block_hash(
        &self,
        block: reth_primitives::BlockHash,
    ) -> reth_interfaces::RethResult<reth_provider::StateProviderBox<'_>> {
        unimplemented!()
    }
    fn history_by_block_number(
        &self,
        block: reth_primitives::BlockNumber,
    ) -> reth_interfaces::RethResult<reth_provider::StateProviderBox<'_>> {
        unimplemented!()
    }
    fn latest(&self) -> reth_interfaces::RethResult<reth_provider::StateProviderBox> {
        Ok(Box::new(self))
    }
    fn pending(&self) -> reth_interfaces::RethResult<reth_provider::StateProviderBox<'_>> {
        unimplemented!()
    }
    fn pending_state_by_hash(
        &self,
        block_hash: H256,
    ) -> reth_interfaces::RethResult<Option<reth_provider::StateProviderBox<'_>>> {
        unimplemented!()
    }
    fn pending_with_provider(
        &self,
        post_state_data: Box<dyn reth_provider::BundleStateDataProvider>,
    ) -> reth_interfaces::RethResult<reth_provider::StateProviderBox<'_>> {
        unimplemented!()
    }
    fn state_by_block_hash(
        &self,
        block: reth_primitives::BlockHash,
    ) -> reth_interfaces::RethResult<reth_provider::StateProviderBox<'_>> {
        unimplemented!()
    }
    fn state_by_block_id(
        &self,
        block_id: reth_primitives::BlockId,
    ) -> reth_interfaces::RethResult<reth_provider::StateProviderBox<'_>> {
        unimplemented!()
    }
    fn state_by_block_number_or_tag(
        &self,
        number_or_tag: reth_primitives::BlockNumberOrTag,
    ) -> reth_interfaces::RethResult<reth_provider::StateProviderBox<'_>> {
        unimplemented!()
    }
}

impl<C: sov_modules_api::Context> BlockReaderIdExt for DbProvider<C> {
    fn block_by_id(
        &self,
        id: reth_primitives::BlockId,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Block>> {
        unimplemented!()
    }
    fn block_by_number_or_tag(
        &self,
        id: reth_primitives::BlockNumberOrTag,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Block>> {
        unimplemented!()
    }
    fn finalized_header(
        &self,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!()
    }
    fn header_by_id(
        &self,
        id: reth_primitives::BlockId,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Header>> {
        unimplemented!()
    }
    fn header_by_number_or_tag(
        &self,
        id: reth_primitives::BlockNumberOrTag,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Header>> {
        unimplemented!()
    }
    fn latest_header(&self) -> reth_interfaces::RethResult<Option<reth_primitives::SealedHeader>> {
        let latest_header = {
            let mut working_set = WorkingSet::<C>::new(self.storage.clone());
            Some(self.evm.latest_header(&mut working_set))
        };
        Ok(latest_header)
    }
    fn ommers_by_id(
        &self,
        id: reth_primitives::BlockId,
    ) -> reth_interfaces::RethResult<Option<Vec<reth_primitives::Header>>> {
        unimplemented!()
    }
    fn ommers_by_number_or_tag(
        &self,
        id: reth_primitives::BlockNumberOrTag,
    ) -> reth_interfaces::RethResult<Option<Vec<reth_primitives::Header>>> {
        unimplemented!()
    }
    fn pending_header(&self) -> reth_interfaces::RethResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!()
    }
    fn safe_header(&self) -> reth_interfaces::RethResult<Option<reth_primitives::SealedHeader>> {
        todo!("safe_header")
    }
    fn sealed_header_by_id(
        &self,
        id: reth_primitives::BlockId,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::SealedHeader>> {
        todo!("sealed_header_by_id")
    }
    fn sealed_header_by_number_or_tag(
        &self,
        id: reth_primitives::BlockNumberOrTag,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::SealedHeader>> {
        todo!("sealed_header_by_number_or_tag")
    }
}

impl<C: sov_modules_api::Context> AccountReader for DbProvider<C> {
    #[doc = r" Get basic account information."]
    #[doc = r""]
    #[doc = r" Returns `None` if the account doesn't exist."]
    fn basic_account(&self, address: Address) -> RethResult<Option<Account>> {
        let account = {
            let mut working_set = WorkingSet::<C>::new(self.storage.clone());
            self.evm.basic_account(&address, &mut working_set)
        };
        Ok(account)
    }
}

impl<C: sov_modules_api::Context> StateRootProvider for DbProvider<C> {
    #[doc = r" Returns the state root of the BundleState on top of the current state."]
    fn state_root(&self, post_state: BundleStateWithReceipts) -> RethResult<H256> {
        todo!()
    }
}

impl<C: sov_modules_api::Context> StateProvider for DbProvider<C> {
    fn account_balance(&self, addr: Address) -> reth_interfaces::RethResult<Option<U256>> {
        todo!("account_balance")
    }
    fn account_code(
        &self,
        addr: Address,
    ) -> reth_interfaces::RethResult<Option<reth_primitives::Bytecode>> {
        todo!("account_code")
    }

    #[doc = r" Get storage of given account."]
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> RethResult<Option<StorageValue>> {
        todo!()
    }

    #[doc = r" Get account code by its hash"]
    fn bytecode_by_hash(&self, code_hash: H256) -> RethResult<Option<Bytecode>> {
        todo!()
    }

    #[doc = r" Get account and storage proofs."]
    fn proof(
        &self,
        address: Address,
        keys: &[H256],
    ) -> RethResult<(Vec<Bytes>, H256, Vec<Vec<Bytes>>)> {
        todo!()
    }
}
