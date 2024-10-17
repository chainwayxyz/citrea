use core::ops::RangeInclusive;
use std::collections::HashMap;

use alloy_consensus::Header;
use alloy_eips::{BlockHashOrNumber, BlockId};
use alloy_primitives::{
    map::HashSet,
    Address,
    BlockHash,
    // map::{HashMap, HashSet},
    BlockNumber,
    Bytes,
    StorageKey,
    StorageValue,
    TxHash,
    TxNumber,
    B256,
    U256,
};
use alloy_rpc_types::{Block, BlockTransactions};
use alloy_serde::WithOtherFields;
use citrea_evm::{Evm, EvmChainConfig};
use jsonrpsee::core::RpcResult;
use reth_chainspec::{ChainInfo, ChainSpec};
use reth_db::models::StoredBlockBodyIndices;
use reth_primitives::{
    Account, BlockNumberOrTag, BlockWithSenders, Bytecode, SealedBlockWithSenders, SealedHeader,
};
use reth_provider::{
    AccountReader, BlockHashReader, BlockIdReader, BlockNumReader, BlockReader, BlockReaderIdExt,
    ChainSpecProvider, HeaderProvider, ProviderResult, ReceiptProvider, ReceiptProviderIdExt,
    RequestsProvider, StateProofProvider, StateProvider, StateProviderFactory, StateRootProvider,
    StorageRootProvider, TransactionsProvider, WithdrawalsProvider,
};
use reth_trie::updates::TrieUpdates;
use reth_trie::{
    AccountProof, HashedPostState, HashedStorage, MultiProof, StorageProof, TrieInput,
};
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

    pub fn last_block_tx_hashes(&self) -> RpcResult<Vec<B256>> {
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());
        let rich_block = self.evm.get_block_by_number(None, None, &mut working_set)?;
        let hashes = rich_block.map(|b| b.inner.transactions);
        match hashes {
            Some(BlockTransactions::Hashes(hashes)) => Ok(hashes),
            _ => Ok(vec![]),
        }
    }

    pub fn last_block(
        &self,
    ) -> RpcResult<Option<WithOtherFields<Block<WithOtherFields<alloy_rpc_types::Transaction>>>>>
    {
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());
        let rich_block = self
            .evm
            .get_block_by_number(None, Some(true), &mut working_set)?;
        Ok(rich_block)
    }

    pub fn genesis_block(
        &self,
    ) -> RpcResult<Option<Block<WithOtherFields<alloy_rpc_types::Transaction>>>> {
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());
        let rich_block = self
            .evm
            .get_block_by_number(Some(BlockNumberOrTag::Earliest), None, &mut working_set)?
            .map(|b| b.inner);
        Ok(rich_block)
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

impl<C: sov_modules_api::Context> RequestsProvider for DbProvider<C> {
    fn requests_by_block(
        &self,
        _id: BlockHashOrNumber,
        _timestamp: u64,
    ) -> ProviderResult<Option<reth_primitives::Requests>> {
        unimplemented!("requests_by_block")
    }
}

impl<C: sov_modules_api::Context> BlockReaderIdExt for DbProvider<C> {
    fn block_by_id(&self, _id: BlockId) -> ProviderResult<Option<reth_primitives::Block>> {
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
    fn header_by_id(&self, _id: BlockId) -> ProviderResult<Option<Header>> {
        unimplemented!("header_by_id")
    }
    fn header_by_number_or_tag(
        &self,
        _id: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<Header>> {
        unimplemented!("header_by_number_or_tag")
    }
    fn latest_header(&self) -> ProviderResult<Option<SealedHeader>> {
        let latest_header = {
            let mut working_set = WorkingSet::<C>::new(self.storage.clone());
            self.evm.last_sealed_header(&mut working_set)
        };
        Ok(Some(latest_header))
    }
    fn ommers_by_id(&self, _id: BlockId) -> ProviderResult<Option<Vec<Header>>> {
        unimplemented!("ommers_by_id")
    }
    fn ommers_by_number_or_tag(
        &self,
        _id: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<Vec<Header>>> {
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
        _id: BlockId,
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
    fn header(&self, _block_hash: &BlockHash) -> ProviderResult<Option<Header>> {
        unimplemented!("header")
    }
    fn header_by_hash_or_number(
        &self,
        _hash_or_num: BlockHashOrNumber,
    ) -> ProviderResult<Option<Header>> {
        unimplemented!("header_by_hash_or_number")
    }
    fn header_by_number(&self, _num: u64) -> ProviderResult<Option<Header>> {
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
    ) -> ProviderResult<Vec<Header>> {
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

impl<C: sov_modules_api::Context> BlockHashReader for DbProvider<C> {
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
        _hash_or_number: alloy_rpc_types::BlockHashOrNumber,
    ) -> ProviderResult<Option<B256>> {
        unimplemented!("convert_block_hash")
    }
}

impl<C: sov_modules_api::Context> BlockNumReader for DbProvider<C> {
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

impl<C: sov_modules_api::Context> BlockIdReader for DbProvider<C> {
    fn block_hash_for_id(&self, _block_id: BlockId) -> ProviderResult<Option<B256>> {
        unimplemented!("block_hash_for_id")
    }
    fn block_number_for_id(&self, _block_id: BlockId) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("block_number_for_id")
    }
    fn convert_block_number(
        &self,
        _num: reth_primitives::BlockNumberOrTag,
    ) -> ProviderResult<Option<BlockNumber>> {
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

impl<C: sov_modules_api::Context> BlockReader for DbProvider<C> {
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
        _id: alloy_rpc_types::BlockHashOrNumber,
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
    fn ommers(&self, _id: BlockHashOrNumber) -> ProviderResult<Option<Vec<Header>>> {
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

impl<C: sov_modules_api::Context> TransactionsProvider for DbProvider<C> {
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

impl<C: sov_modules_api::Context> ReceiptProvider for DbProvider<C> {
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

impl<C: sov_modules_api::Context> ReceiptProviderIdExt for DbProvider<C> {
    fn receipts_by_block_id(
        &self,
        _block: BlockId,
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
        _id: BlockHashOrNumber,
        _timestamp: u64,
    ) -> ProviderResult<Option<reth_primitives::Withdrawals>> {
        unimplemented!("withdrawals_by_block")
    }
}

impl<C: sov_modules_api::Context> ChainSpecProvider for DbProvider<C> {
    type ChainSpec = ChainSpec;
    fn chain_spec(&self) -> std::sync::Arc<ChainSpec> {
        unimplemented!("chain_spec")
    }
}

impl<C: sov_modules_api::Context> StateProviderFactory for DbProvider<C> {
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
        _block_id: BlockId,
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
    fn state_root(&self, _bundle_state: HashedPostState) -> ProviderResult<B256> {
        unimplemented!("state_root")
    }
    fn state_root_with_updates(
        &self,
        _bundle_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        unimplemented!("state_root_with_updates")
    }

    #[doc = " Returns the state root of the `HashedPostState` on top of the current state but re-uses the"]
    #[doc = " intermediate nodes to speed up the computation. It\'s up to the caller to construct the"]
    #[doc = " prefix sets and inform the provider of the trie paths that have changes."]
    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        unimplemented!("state_root_from_nodes")
    }

    #[doc = " Returns state root and trie updates."]
    #[doc = " See [`StateRootProvider::state_root_from_nodes`] for more info."]
    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        unimplemented!("state_root_from_nodes_with_updates")
    }
}

impl<C: sov_modules_api::Context> StateProofProvider for DbProvider<C> {
    fn witness(
        &self,
        _overlay: reth_trie::TrieInput,
        _target: reth_trie::HashedPostState,
    ) -> ProviderResult<HashMap<B256, Bytes>> {
        unimplemented!("hashed_proof")
    }

    #[doc = " Get account and storage proofs of target keys in the `HashedPostState`"]
    #[doc = " on top of the current state."]
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        unimplemented!("proof")
    }

    #[doc = " Generate [`MultiProof`] for target hashed account and corresponding"]
    #[doc = " hashed storage slot keys."]
    fn multiproof(
        &self,
        input: TrieInput,
        targets: HashMap<B256, HashSet<B256>>,
    ) -> ProviderResult<MultiProof> {
        unimplemented!("multiproof")
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

    fn bytecode_by_hash(&self, _code_hash: B256) -> ProviderResult<Option<Bytecode>> {
        unimplemented!("bytecode_by_hash")
    }

    fn account_nonce(&self, _addr: Address) -> ProviderResult<Option<u64>> {
        unimplemented!("account_nonce")
    }
}

impl<C: sov_modules_api::Context> StorageRootProvider for DbProvider<C> {
    #[doc = " Returns the storage root of the `HashedStorage` for target address on top of the current"]
    #[doc = " state."]
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        todo!()
    }

    #[doc = " Returns the storage proof of the `HashedStorage` for target slot on top of the current"]
    #[doc = " state."]
    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        todo!()
    }
}
