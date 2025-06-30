use core::ops::RangeInclusive;
use std::fmt::Debug;

use alloy_eips::{BlockHashOrNumber, BlockId, BlockNumberOrTag};
use alloy_genesis::Genesis;
use alloy_primitives::{
    Address, BlockHash, BlockNumber, Bytes, StorageKey, StorageValue, TxHash, TxNumber, B256, U256,
};
use alloy_rpc_types::{BlockTransactions, Withdrawals};
use alloy_rpc_types_eth::Block as AlloyRpcBlock;
use alloy_serde::WithOtherFields;
use citrea_evm::{Evm, EvmChainConfig};
use citrea_stf::runtime::DefaultContext;
use jsonrpsee::core::RpcResult;
use reth_chainspec::{Chain, ChainInfo, ChainSpec, ChainSpecBuilder};
use reth_primitives::{Account, Bytecode, RecoveredBlock, SealedHeader};
use reth_provider::{
    AccountReader, BlockBodyIndicesProvider, BlockHashReader, BlockIdReader, BlockNumReader,
    BlockReader, BlockReaderIdExt, ChainSpecProvider, HashedPostStateProvider, HeaderProvider,
    OmmersProvider, ProviderError, ProviderResult, ReceiptProvider, ReceiptProviderIdExt,
    StateProofProvider, StateProvider, StateProviderFactory, StateRootProvider,
    StorageRootProvider, TransactionVariant, TransactionsProvider, WithdrawalsProvider,
};
use reth_trie::updates::TrieUpdates;
use reth_trie::{HashedPostState, HashedStorage, StorageMultiProof, StorageProof};
use revm::database::BundleState;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::{Spec, WorkingSet};

/// Provider for EVM database operations in the sequencer
///
/// This struct primarily exists for reth compatibility, implementing various traits
/// from the Reth ecosystem to provide access to blockchain data. While many trait
/// methods are marked as `unimplemented!()`, they can be implemented as needed -
/// they were left unimplemented as they weren't required for our current use cases.
///
/// The provider handles access to:
/// - Blocks
/// - Transactions
/// - Receipts
/// - State information
#[derive(Clone)]
pub struct DbProvider {
    /// The EVM instance for executing transactions
    pub evm: Evm<DefaultContext>,
    /// Storage for the sequencer state
    pub storage: <DefaultContext as Spec>::Storage,
    /// LedgerDb
    ledger_db: LedgerDB,
}

impl Debug for DbProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbProvider").finish()
    }
}

impl DbProvider {
    /// Creates a new DbProvider instance with the given storage
    ///
    /// # Arguments
    /// * `storage` - The storage implementation to use
    pub fn new(storage: <DefaultContext as Spec>::Storage, ledger_db: LedgerDB) -> Self {
        let evm = Evm::<DefaultContext>::default();
        Self {
            evm,
            storage,
            ledger_db,
        }
    }

    /// Returns the current EVM chain configuration
    pub fn cfg(&self) -> EvmChainConfig {
        let mut working_set = WorkingSet::new(self.storage.clone());
        self.evm.get_chain_config(&mut working_set)
    }

    /// Returns the transaction hashes from the last block
    pub fn last_block_tx_hashes(&self) -> RpcResult<Vec<B256>> {
        let mut working_set = WorkingSet::new(self.storage.clone());
        let rich_block =
            self.evm
                .get_block_by_number(None, None, &mut working_set, &self.ledger_db)?;
        let hashes = rich_block.map(|b| b.inner.transactions);
        match hashes {
            Some(BlockTransactions::Hashes(hashes)) => Ok(hashes),
            _ => Ok(vec![]),
        }
    }

    /// Returns the last block with full transaction details
    pub fn last_block(&self) -> RpcResult<Option<WithOtherFields<AlloyRpcBlock>>> {
        let mut working_set = WorkingSet::new(self.storage.clone());
        let rich_block =
            self.evm
                .get_block_by_number(None, Some(true), &mut working_set, &self.ledger_db)?;
        Ok(rich_block)
    }

    /// Returns the genesis block
    pub fn genesis_block(&self) -> RpcResult<Option<WithOtherFields<AlloyRpcBlock>>> {
        let mut working_set = WorkingSet::new(self.storage.clone());
        let rich_block = self.evm.get_block_by_number(
            Some(BlockNumberOrTag::Earliest),
            None,
            &mut working_set,
            &self.ledger_db,
        )?;

        Ok(rich_block)
    }
}

impl AccountReader for DbProvider {
    #[doc = r" Get basic account information."]
    #[doc = r""]
    #[doc = r" Returns `None` if the account doesn't exist."]
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        let account = {
            let mut working_set = WorkingSet::new(self.storage.clone());
            self.evm
                .account_info(address, &mut working_set)
                .map(Into::into)
        };
        Ok(account)
    }
}

impl OmmersProvider for DbProvider {
    fn ommers(&self, _id: BlockHashOrNumber) -> ProviderResult<Option<Vec<Self::Header>>> {
        unimplemented!("ommers")
    }
}

impl BlockBodyIndicesProvider for DbProvider {
    fn block_body_indices(
        &self,
        _num: u64,
    ) -> ProviderResult<Option<reth_db::models::StoredBlockBodyIndices>> {
        unimplemented!("block_body_indices")
    }
    fn block_body_indices_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<reth_db::models::StoredBlockBodyIndices>> {
        unimplemented!("block_body_indices_range")
    }
}

impl BlockReaderIdExt for DbProvider {
    fn block_by_id(&self, _id: BlockId) -> ProviderResult<Option<Self::Block>> {
        unimplemented!("block_by_id")
    }
    fn finalized_header(&self) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("finalized_header")
    }
    fn header_by_id(&self, _id: BlockId) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_id")
    }
    fn header_by_number_or_tag(
        &self,
        _id: BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::Header>> {
        unimplemented!("header_by_number_or_tag")
    }
    fn ommers_by_id(&self, _id: BlockId) -> ProviderResult<Option<Vec<reth_primitives::Header>>> {
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
    /// Gets a sealed header by block ID
    ///
    /// # Arguments
    /// * `id` - Block identifier (number or hash)
    ///
    /// # Returns
    /// The sealed header if found, wrapped in a ProviderResult
    fn sealed_header_by_id(
        &self,
        id: BlockId,
    ) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        let mut working_set = WorkingSet::new(self.storage.clone());

        let block_num = match id {
            BlockId::Number(num) => num,
            BlockId::Hash(hash) => {
                let block_num = self
                    .evm
                    .get_block_number_by_block_hash(hash.block_hash, &mut working_set)
                    .ok_or(ProviderError::BlockHashNotFound(hash.block_hash))?;

                BlockNumberOrTag::Number(block_num)
            }
        };

        let block = self
            .evm
            .get_block_by_number(Some(block_num), None, &mut working_set, &self.ledger_db)
            .unwrap()
            .unwrap();
        let hash = block.header.hash;

        Ok(Some(SealedHeader::new(
            block.inner.header.into_consensus(),
            hash,
        )))
    }

    fn sealed_header_by_number_or_tag(
        &self,
        _id: BlockNumberOrTag,
    ) -> ProviderResult<Option<reth_primitives::SealedHeader>> {
        unimplemented!("sealed_header_by_number_or_tag")
    }
}

impl HeaderProvider for DbProvider {
    type Header = reth_primitives::Header;
    fn header(&self, _block_hash: &BlockHash) -> ProviderResult<Option<Self::Header>> {
        unimplemented!("header")
    }
    fn header_by_number(&self, _num: u64) -> ProviderResult<Option<Self::Header>> {
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
    ) -> ProviderResult<Vec<Self::Header>> {
        unimplemented!("headers_range")
    }
    fn sealed_header(
        &self,
        _number: BlockNumber,
    ) -> ProviderResult<Option<SealedHeader<Self::Header>>> {
        unimplemented!("sealed_header")
    }
    fn sealed_headers_while(
        &self,
        _range: impl std::ops::RangeBounds<BlockNumber>,
        _predicate: impl FnMut(&SealedHeader<Self::Header>) -> bool,
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
    fn block_hash_for_id(&self, _block_id: BlockId) -> ProviderResult<Option<B256>> {
        unimplemented!("block_hash_for_id")
    }
    fn block_number_for_id(&self, _block_id: BlockId) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("block_number_for_id")
    }
    fn convert_block_number(&self, _num: BlockNumberOrTag) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("convert_block_number")
    }
    fn finalized_block_hash(&self) -> ProviderResult<Option<B256>> {
        unimplemented!("finalized_block_hash")
    }
    fn finalized_block_num_hash(&self) -> ProviderResult<Option<alloy_eips::BlockNumHash>> {
        unimplemented!("finalized_block_num_hash")
    }
    fn finalized_block_number(&self) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("finalized_block_number")
    }
    fn pending_block_num_hash(&self) -> ProviderResult<Option<alloy_eips::BlockNumHash>> {
        unimplemented!("pending_block_num_hash")
    }
    fn safe_block_hash(&self) -> ProviderResult<Option<B256>> {
        unimplemented!("safe_block_hash")
    }
    fn safe_block_num_hash(&self) -> ProviderResult<Option<alloy_eips::BlockNumHash>> {
        unimplemented!("safe_block_num_hash")
    }
    fn safe_block_number(&self) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("safe_block_number")
    }
}

impl BlockReader for DbProvider {
    type Block = reth_primitives::Block;
    fn block(&self, _id: BlockHashOrNumber) -> ProviderResult<Option<Self::Block>> {
        unimplemented!("block")
    }
    fn find_block_by_hash(
        &self,
        _hash: B256,
        _source: reth_provider::BlockSource,
    ) -> ProviderResult<Option<reth_primitives::Block>> {
        unimplemented!("find_block_by_hash")
    }
    fn pending_block(&self) -> ProviderResult<Option<reth_primitives::SealedBlock>> {
        unimplemented!("pending_block")
    }
    fn pending_block_and_receipts(
        &self,
    ) -> ProviderResult<Option<(reth_primitives::SealedBlock, Vec<reth_primitives::Receipt>)>> {
        unimplemented!("pending_block_and_receipts")
    }
    fn recovered_block(
        &self,
        _id: BlockHashOrNumber,
        _transaction_kind: TransactionVariant,
    ) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        unimplemented!("recovered_block")
    }
    fn block_range(
        &self,
        _range: std::ops::RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<reth_primitives::Block>> {
        unimplemented!("block_range")
    }
    fn pending_block_with_senders(&self) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        unimplemented!("pending_block_with_senders")
    }
    fn block_with_senders_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<RecoveredBlock<Self::Block>>> {
        unimplemented!("block_with_senders_range")
    }

    fn sealed_block_with_senders(
        &self,
        _id: BlockHashOrNumber,
        _transaction_kind: reth_provider::TransactionVariant,
    ) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        unimplemented!("sealed_block_with_senders")
    }

    fn recovered_block_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<RecoveredBlock<Self::Block>>> {
        unimplemented!("recovered_block_range")
    }
}

impl TransactionsProvider for DbProvider {
    type Transaction = reth_primitives::TransactionSigned;
    fn senders_by_tx_range(
        &self,
        _range: impl std::ops::RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Address>> {
        unimplemented!("senders_by_tx_range")
    }
    fn transaction_block(&self, _id: TxNumber) -> ProviderResult<Option<BlockNumber>> {
        unimplemented!("transaction_block")
    }
    fn transaction_by_hash(&self, _hash: TxHash) -> ProviderResult<Option<Self::Transaction>> {
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
    fn transaction_by_id(&self, _id: TxNumber) -> ProviderResult<Option<Self::Transaction>> {
        unimplemented!("transaction_by_id")
    }
    fn transaction_by_id_unhashed(
        &self,
        _id: TxNumber,
    ) -> ProviderResult<Option<Self::Transaction>> {
        unimplemented!("transaction_by_id_unhashed")
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
    ) -> ProviderResult<Option<Vec<Self::Transaction>>> {
        unimplemented!("transactions_by_block")
    }
    fn transactions_by_block_range(
        &self,
        _range: impl std::ops::RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Vec<Self::Transaction>>> {
        unimplemented!("transactions_by_block_range")
    }
    fn transactions_by_tx_range(
        &self,
        _range: impl std::ops::RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Self::Transaction>> {
        unimplemented!("transactions_by_tx_range")
    }
}

impl ReceiptProvider for DbProvider {
    type Receipt = reth_primitives::Receipt;
    fn receipt(&self, _id: TxNumber) -> ProviderResult<Option<Self::Receipt>> {
        unimplemented!("receipt")
    }
    fn receipt_by_hash(&self, _hash: TxHash) -> ProviderResult<Option<Self::Receipt>> {
        unimplemented!("receipt_by_hash")
    }
    fn receipts_by_block(
        &self,
        _block: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<Self::Receipt>>> {
        unimplemented!("receipts_by_block")
    }
    fn receipts_by_tx_range(
        &self,
        _range: impl std::ops::RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Self::Receipt>> {
        unimplemented!("receipts_by_tx_range")
    }
}

impl ReceiptProviderIdExt for DbProvider {}

impl WithdrawalsProvider for DbProvider {
    fn withdrawals_by_block(
        &self,
        _id: BlockHashOrNumber,
        _timestamp: u64,
    ) -> ProviderResult<Option<Withdrawals>> {
        unimplemented!("withdrawals_by_block")
    }
}

impl ChainSpecProvider for DbProvider {
    type ChainSpec = ChainSpec;
    fn chain_spec(&self) -> std::sync::Arc<ChainSpec> {
        let cfg = self.cfg();

        let genesis_block = self.genesis_block().unwrap().unwrap();

        let chain_spec = ChainSpecBuilder::default()
            .chain(Chain::from_id(cfg.chain_id))
            .shanghai_activated()
            .cancun_activated()
            .prague_activated()
            .genesis(
                Genesis::default()
                    .with_nonce(genesis_block.header.nonce.into())
                    .with_timestamp(genesis_block.header.timestamp)
                    .with_extra_data(genesis_block.header.extra_data.clone())
                    .with_gas_limit(genesis_block.header.gas_limit)
                    .with_difficulty(genesis_block.header.difficulty)
                    .with_mix_hash(genesis_block.header.mix_hash)
                    .with_coinbase(genesis_block.header.beneficiary)
                    .with_base_fee(genesis_block.header.base_fee_per_gas.map(Into::into)),
            )
            .build();

        std::sync::Arc::new(chain_spec)
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
        _block_id: BlockId,
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
        _targets: reth_trie::MultiProofTargets,
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
    ) -> ProviderResult<Vec<Bytes>> {
        unimplemented!("hashed_proof")
    }
}

impl StorageRootProvider for DbProvider {
    fn storage_root(
        &self,
        _address: Address,
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        unimplemented!("storage_root")
    }

    fn storage_proof(
        &self,
        _address: Address,
        _slot: B256,
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        unimplemented!("storage_proof")
    }

    fn storage_multiproof(
        &self,
        _address: Address,
        _slots: &[B256],
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        unimplemented!("storage_multiproof")
    }
}

impl HashedPostStateProvider for DbProvider {
    fn hashed_post_state(&self, _bundle_state: &BundleState) -> HashedPostState {
        unimplemented!("hashed_post_state")
    }
}

impl StateProvider for DbProvider {
    fn storage(
        &self,
        _account: Address,
        _storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        unimplemented!("storage")
    }

    fn bytecode_by_hash(&self, _code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        unimplemented!("bytecode_by_hash")
    }
}
