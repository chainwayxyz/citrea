use core::ops::RangeInclusive;

use alloy_primitives::map::{HashMap, HashSet};
use alloy_primitives::{
    Address, BlockHash, BlockNumber, Bytes, StorageKey, StorageValue, TxHash, TxNumber, B256, U256,
};
use alloy_rpc_types::{AnyNetworkBlock, BlockTransactions};
use citrea_evm::{Evm, EvmChainConfig};
use citrea_stf::runtime::DefaultContext;
use jsonrpsee::core::RpcResult;
use reth_chainspec::{ChainInfo, ChainSpec};
use reth_db::models::StoredBlockBodyIndices;
use reth_primitives::{
    Account, BlockHashOrNumber, BlockNumberOrTag, BlockWithSenders, Bytecode,
    SealedBlockWithSenders, SealedHeader,
};
use reth_provider::{
    AccountReader, BlockHashReader, BlockIdReader, BlockNumReader, BlockReader, BlockReaderIdExt,
    ChainSpecProvider, HeaderProvider, ProviderResult, ReceiptProvider, ReceiptProviderIdExt,
    RequestsProvider, StateProofProvider, StateProvider, StateProviderFactory, StateRootProvider,
    StorageRootProvider, TransactionsProvider, WithdrawalsProvider,
};
use reth_trie::updates::TrieUpdates;
use reth_trie::{HashedPostState, HashedStorage, StorageProof};
use sov_modules_api::{Spec, WorkingSet};

#[derive(Clone)]
pub struct DbProvider {
    pub evm: Evm<DefaultContext>,
    pub storage: <DefaultContext as Spec>::Storage,
}

impl DbProvider {
    pub fn new(storage: <DefaultContext as Spec>::Storage) -> Self {
        let evm = Evm::<DefaultContext>::default();
        Self { evm, storage }
    }

    pub fn cfg(&self) -> EvmChainConfig {
        let mut working_set = WorkingSet::new(self.storage.clone());
        self.evm.get_chain_config(&mut working_set)
    }

    pub fn last_block_tx_hashes(&self) -> RpcResult<Vec<B256>> {
        let mut working_set = WorkingSet::new(self.storage.clone());
        let rich_block = self.evm.get_block_by_number(None, None, &mut working_set)?;
        let hashes = rich_block.map(|b| b.inner.transactions);
        match hashes {
            Some(BlockTransactions::Hashes(hashes)) => Ok(hashes),
            _ => Ok(vec![]),
        }
    }

    pub fn last_block(&self) -> RpcResult<Option<AnyNetworkBlock>> {
        let mut working_set = WorkingSet::new(self.storage.clone());
        let rich_block = self
            .evm
            .get_block_by_number(None, Some(true), &mut working_set)?;
        Ok(rich_block)
    }

    pub fn genesis_block(&self) -> RpcResult<Option<AnyNetworkBlock>> {
        let mut working_set = WorkingSet::new(self.storage.clone());
        let rich_block = self.evm.get_block_by_number(
            Some(BlockNumberOrTag::Earliest),
            None,
            &mut working_set,
        )?;

        Ok(rich_block)
    }
}

impl AccountReader for DbProvider {
    #[doc = r" Get basic account information."]
    #[doc = r""]
    #[doc = r" Returns `None` if the account doesn't exist."]
    fn basic_account(&self, address: Address) -> ProviderResult<Option<Account>> {
        let account = {
            let mut working_set = WorkingSet::new(self.storage.clone());
            self.evm
                .account_info(&address, &mut working_set)
                .map(Into::into)
        };
        Ok(account)
    }
}

impl RequestsProvider for DbProvider {
    fn requests_by_block(
        &self,
        _id: BlockHashOrNumber,
        _timestamp: u64,
    ) -> ProviderResult<Option<reth_primitives::Requests>> {
        unimplemented!("requests_by_block")
    }
}

impl BlockReaderIdExt for DbProvider {
    fn block_by_id(
        &self,
        _id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("block_by_id")
    }
    fn block_by_number_or_tag(
        &self,
        _id: BlockNumberOrTag,
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
        _id: BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_number_or_tag")
    }
    fn latest_header(&self) -> ProviderResult<Option<SealedHeader>> {
        let latest_header = {
            let mut working_set = WorkingSet::new(self.storage.clone());
            self.evm.last_sealed_header(&mut working_set)
        };
        Ok(Some(latest_header))
    }
    fn ommers_by_id(
        &self,
        _id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<Vec<reth_primitives::Header>>> {
        unimplemented!("ommers_by_id")
    }
    fn ommers_by_number_or_tag(
        &self,
        _id: BlockNumberOrTag,
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
        _id: BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_header_by_number_or_tag")
    }
}

impl HeaderProvider for DbProvider {
    fn header(&self, _block_hash: &BlockHash) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header")
    }
    fn header_by_hash_or_number(
        &self,
        _hash_or_num: BlockHashOrNumber,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_hash_or_number")
    }
    fn header_by_number(&self, _num: u64) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_number")
    }
    fn header_td(&self, _hash: &BlockHash) -> ProviderResult<Option<U256>> {
        unimplemented!("header_td")
    }
    fn header_td_by_number(&self, _number: BlockNumber) -> ProviderResult<Option<U256>> {
        unimplemented!("header_td_by_number")
    }
    fn headers_range(
        &self,
        _range: impl std::ops::RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<reth_primitives::Header>> {
        unimplemented!("headers_range")
    }
    fn is_known(&self, _block_hash: &BlockHash) -> ProviderResult<bool> {
        unimplemented!("is_known")
    }
    fn sealed_header(
        &self,
        _number: BlockNumber,
    ) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_header")
    }
    fn sealed_headers_range(
        &self,
        _range: impl std::ops::RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_headers_range")
    }
    fn sealed_headers_while(
        &self,
        _range: impl std::ops::RangeBounds<BlockNumber>,
        _predicate: impl FnMut(&SealedHeader) -> bool,
    ) -> ProviderResult<Vec<SealedHeader>> {
        unimplemented!("sealed_headers_while")
    }
}

impl BlockHashReader for DbProvider {
    fn block_hash(&self, _number: BlockNumber) -> ProviderResult<Option<B256>> {
        unimplemented!()
    }
    fn canonical_hashes_range(
        &self,
        _start: BlockNumber,
        _end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        unimplemented!("canonical_hashes_range")
    }
    fn convert_block_hash(
        &self,
        _hash_or_number: BlockHashOrNumber,
    ) -> ProviderResult<Option<B256>> {
        unimplemented!("convert_block_hash")
    }
}

impl BlockNumReader for DbProvider {
    fn best_block_number(&self) -> ProviderResult<BlockNumber> {
        unimplemented!("best_block_number")
    }
    fn block_number(&self, _hash: B256) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("block_number")
    }
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        unimplemented!("chain_info")
    }
    fn convert_hash_or_number(
        &self,
        _id: BlockHashOrNumber,
    ) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("convert_hash_or_number")
    }
    fn convert_number(&self, _id: BlockHashOrNumber) -> ProviderResult<Option<B256>> {
        unimplemented!("convert_number")
    }
    fn last_block_number(&self) -> ProviderResult<BlockNumber> {
        unimplemented!("last_block_number")
    }
}

impl BlockIdReader for DbProvider {
    fn block_hash_for_id(
        &self,
        _block_id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<B256>> {
        unimplemented!("block_hash_for_id")
    }
    fn block_number_for_id(
        &self,
        _block_id: reth_primitives::BlockId,
    ) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("block_number_for_id")
    }
    fn convert_block_number(&self, _num: BlockNumberOrTag) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("convert_block_number")
    }
    fn finalized_block_hash(&self) -> ProviderResult<Option<B256>> {
        unimplemented!("finalized_block_hash")
    }
    fn finalized_block_num_hash(&self) -> ProviderResult<Option<reth_primitives::BlockNumHash>> {
        unimplemented!("finalized_block_num_hash")
    }
    fn finalized_block_number(&self) -> ProviderResult<Option<BlockNumber>> {
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
    fn safe_block_number(&self) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("safe_block_number")
    }
}

impl BlockReader for DbProvider {
    fn block(&self, _id: BlockHashOrNumber) -> ProviderResult<Option<reth_primitives::Block>> {
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
        _id: BlockHashOrNumber,
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
        _id: BlockHashOrNumber,
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
        _range: std::ops::RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<reth_primitives::Block>> {
        unimplemented!("block_range")
    }
    fn pending_block_with_senders(
        &self,
    ) -> ProviderResult<Option<reth_primitives::SealedBlockWithSenders>> {
        unimplemented!("pending_block_with_senders")
    }
    fn block_with_senders_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<BlockWithSenders>> {
        unimplemented!("block_with_senders_range")
    }

    fn sealed_block_with_senders(
        &self,
        _id: BlockHashOrNumber,
        _transaction_kind: reth_provider::TransactionVariant,
    ) -> ProviderResult<Option<SealedBlockWithSenders>> {
        unimplemented!("sealed_block_with_senders")
    }

    fn sealed_block_with_senders_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<SealedBlockWithSenders>> {
        unimplemented!("sealed_block_with_senders_range")
    }
}

impl TransactionsProvider for DbProvider {
    fn senders_by_tx_range(
        &self,
        _range: impl std::ops::RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Address>> {
        unimplemented!("senders_by_tx_range")
    }
    fn transaction_block(&self, _id: TxNumber) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("transaction_block")
    }
    fn transaction_by_hash(
        &self,
        _hash: TxHash,
    ) -> ProviderResult<Option<reth_primitives::TransactionSigned>> {
        unimplemented!("transaction_by_hash")
    }
    fn transaction_by_hash_with_meta(
        &self,
        _hash: TxHash,
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
        _id: TxNumber,
    ) -> ProviderResult<Option<reth_primitives::TransactionSigned>> {
        unimplemented!("transaction_by_id")
    }
    fn transaction_by_id_no_hash(
        &self,
        _id: TxNumber,
    ) -> ProviderResult<Option<reth_primitives::TransactionSignedNoHash>> {
        unimplemented!("transaction_by_id_no_hash")
    }
    fn transaction_id(&self, _tx_hash: TxHash) -> ProviderResult<Option<TxNumber>> {
        unimplemented!("transaction_id")
    }
    fn transaction_sender(&self, _id: TxNumber) -> ProviderResult<Option<Address>> {
        unimplemented!("transaction_sender")
    }
    fn transactions_by_block(
        &self,
        _block: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<reth_primitives::TransactionSigned>>> {
        unimplemented!("transactions_by_block")
    }
    fn transactions_by_block_range(
        &self,
        _range: impl std::ops::RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Vec<reth_primitives::TransactionSigned>>> {
        unimplemented!("transactions_by_block_range")
    }
    fn transactions_by_tx_range(
        &self,
        _range: impl std::ops::RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<reth_primitives::TransactionSignedNoHash>> {
        unimplemented!("transactions_by_tx_range")
    }
}

impl ReceiptProvider for DbProvider {
    fn receipt(&self, _id: TxNumber) -> ProviderResult<Option<reth_primitives::Receipt>> {
        unimplemented!("receipt")
    }
    fn receipt_by_hash(&self, _hash: TxHash) -> ProviderResult<Option<reth_primitives::Receipt>> {
        unimplemented!("receipt_by_hash")
    }
    fn receipts_by_block(
        &self,
        _block: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!("receipts_by_block")
    }
    fn receipts_by_tx_range(
        &self,
        _range: impl std::ops::RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<reth_primitives::Receipt>> {
        unimplemented!("receipts_by_tx_range")
    }
}

impl ReceiptProviderIdExt for DbProvider {
    fn receipts_by_block_id(
        &self,
        _block: reth_primitives::BlockId,
    ) -> ProviderResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!("receipts_by_block_id")
    }
    fn receipts_by_number_or_tag(
        &self,
        _number_or_tag: BlockNumberOrTag,
    ) -> ProviderResult<Option<Vec<reth_primitives::Receipt>>> {
        unimplemented!("receipts_by_number_or_tag")
    }
}

impl WithdrawalsProvider for DbProvider {
    fn latest_withdrawal(&self) -> ProviderResult<Option<reth_primitives::Withdrawal>> {
        unimplemented!("latest_withdrawal")
    }
    fn withdrawals_by_block(
        &self,
        _id: BlockHashOrNumber,
        _timestamp: u64,
    ) -> ProviderResult<Option<reth_primitives::Withdrawals>> {
        unimplemented!("withdrawals_by_block")
    }
}

impl ChainSpecProvider for DbProvider {
    type ChainSpec = ChainSpec;
    fn chain_spec(&self) -> std::sync::Arc<ChainSpec> {
        unimplemented!("chain_spec")
    }
}

impl StateProviderFactory for DbProvider {
    fn history_by_block_hash(
        &self,
        _block: BlockHash,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!("history_by_block_hash")
    }
    fn history_by_block_number(
        &self,
        _block: BlockNumber,
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
    fn state_by_block_hash(
        &self,
        _block: BlockHash,
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
        _number_or_tag: BlockNumberOrTag,
    ) -> ProviderResult<reth_provider::StateProviderBox> {
        unimplemented!("state_by_block_number_or_tag")
    }
}

impl StateRootProvider for DbProvider {
    #[doc = r" Returns the state root of the BundleState on top of the current state."]
    fn state_root(&self, _hashed_state: HashedPostState) -> ProviderResult<B256> {
        unimplemented!("state_root")
    }
    fn state_root_with_updates(
        &self,
        _hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        unimplemented!("state_root_with_updates")
    }
    fn state_root_from_nodes(&self, _input: reth_trie::TrieInput) -> ProviderResult<B256> {
        unimplemented!("state_root_from_nodes")
    }
    fn state_root_from_nodes_with_updates(
        &self,
        _input: reth_trie::TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        unimplemented!("state_root_from_nodes_with_updates")
    }
}

impl StateProofProvider for DbProvider {
    fn multiproof(
        &self,
        _input: reth_trie::TrieInput,
        _targets: HashMap<B256, HashSet<B256>>,
    ) -> ProviderResult<reth_trie::MultiProof> {
        unimplemented!("multiproof")
    }

    fn proof(
        &self,
        _input: reth_trie::TrieInput,
        _address: Address,
        _slots: &[B256],
    ) -> ProviderResult<reth_trie::AccountProof> {
        unimplemented!("proof")
    }

    fn witness(
        &self,
        _overlay: reth_trie::TrieInput,
        _target: reth_trie::HashedPostState,
    ) -> ProviderResult<HashMap<B256, Bytes>> {
        unimplemented!("hashed_proof")
    }
}

impl StorageRootProvider for DbProvider {
    #[doc = " Returns the storage root of the `HashedStorage` for target address on top of the current"]
    #[doc = " state."]
    fn storage_root(
        &self,
        _address: Address,
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        unimplemented!("storage_root")
    }

    #[doc = " Returns the storage proof of the `HashedStorage` for target slot on top of the current"]
    #[doc = " state."]
    fn storage_proof(
        &self,
        _address: Address,
        _slot: B256,
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        unimplemented!("storage_proof")
    }
}

impl StateProvider for DbProvider {
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

    fn bytecode_by_hash(&self, _code_hash: B256) -> ProviderResult<Option<Bytecode>> {
        unimplemented!("bytecode_by_hash")
    }

    fn account_nonce(&self, _addr: Address) -> ProviderResult<Option<u64>> {
        unimplemented!("account_nonce")
    }
}
