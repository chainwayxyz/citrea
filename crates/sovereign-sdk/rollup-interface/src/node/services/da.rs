//! The da module defines traits used by the full node to interact with the DA layer.

use serde::de::DeserializeOwned;
use serde::Serialize;
#[cfg(feature = "native")]
use tokio::sync::mpsc::UnboundedSender;
#[cfg(feature = "native")]
use tokio::sync::oneshot::Sender as OneshotSender;

use crate::da::BlockHeaderTrait;
#[cfg(feature = "native")]
use crate::da::{DaSpec, DaTxRequest, DaVerifier, SequencerCommitment};
#[cfg(feature = "native")]
use crate::zk::Proof;

/// This type represents a queued request to send_transaction
#[cfg(feature = "native")]
pub struct TxRequestWithNotifier<TxID> {
    /// Data to send.
    pub tx_request: DaTxRequest,
    /// Channel to receive result of the operation.
    pub notify: OneshotSender<Result<TxID, anyhow::Error>>,
}

/// A DaService is the local side of an RPC connection talking to a node of the DA layer
/// It is *not* part of the logic that is zk-proven.
///
/// The DaService has two responsibilities - fetching data from the DA layer, transforming the
/// data into a representation that can be efficiently verified in circuit.
#[cfg(feature = "native")]
#[async_trait::async_trait]
pub trait DaService: Send + Sync + 'static {
    /// A handle to the types used by the DA layer.
    type Spec: DaSpec;

    /// The verifier for this DA layer.
    type Verifier: DaVerifier<Spec = Self::Spec>;

    /// A DA layer block, possibly excluding some irrelevant information.
    type FilteredBlock: SlotData<BlockHeader = <Self::Spec as DaSpec>::BlockHeader>;

    /// Type that allow to consume [`futures::Stream`] of BlockHeaders.
    type HeaderStream: futures::Stream<
        Item = Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error>,
    >;

    /// A transaction ID, used to identify the transaction in the DA layer.
    type TransactionId: Send + PartialEq + Eq + PartialOrd + Ord + core::hash::Hash + Into<[u8; 32]>;

    /// The error type for fallible methods.
    type Error: core::fmt::Debug + Send + Sync + core::fmt::Display;

    /// Fetch the block at the given height, waiting for one to be mined if necessary.
    /// The returned block may not be final, and can be reverted without a consensus violation.
    /// Call it for the same height are allowed to return different results.
    /// Should always returns the block at that height on the best fork.
    async fn get_block_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error>;

    /// Fetch block by hash.
    async fn get_block_by_hash(
        &self,
        hash: <Self::Spec as DaSpec>::SlotHash,
    ) -> Result<Self::FilteredBlock, Self::Error>;

    /// Fetch the [`DaSpec::BlockHeader`] of the last finalized block.
    /// If there's no finalized block yet, it should return an error.
    async fn get_last_finalized_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error>;

    /// Fetch the head block of the most popular fork.
    ///
    /// More like utility method, to provide better user experience
    async fn get_head_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error>;

    /// Extract the relevant proofs from a block.
    async fn extract_relevant_zk_proofs(
        &self,
        block: &Self::FilteredBlock,
        prover_da_pub_key: &[u8],
    ) -> Vec<(usize, Proof)>;

    /// Extract SequencerCommitment's from the block
    fn extract_relevant_sequencer_commitments(
        &self,
        block: &Self::FilteredBlock,
        sequencer_da_pub_key: &[u8],
    ) -> Vec<(usize, SequencerCommitment)>;

    /// Extract the relevant transactions from a block, along with a proof that the extraction has been done correctly.
    /// For example, this method might return all of the blob transactions in rollup's namespace on Celestia,
    /// together with a range proof against the root of the namespaced-merkle-tree, demonstrating that the entire
    /// rollup namespace has been covered.
    #[allow(clippy::type_complexity)]
    fn extract_relevant_blobs_with_proof(
        &self,
        block: &Self::FilteredBlock,
    ) -> (
        Vec<<Self::Spec as DaSpec>::BlobTransaction>,
        <Self::Spec as DaSpec>::InclusionMultiProof,
        <Self::Spec as DaSpec>::CompletenessProof,
    );

    /// Decompress chunks.
    fn decompress_chunks(&self, complete_chunks: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Send a transaction directly to the DA layer.
    /// blob is the serialized and signed transaction.
    /// Returns nothing if the transaction was successfully sent.
    async fn send_transaction(
        &self,
        tx_request: DaTxRequest,
    ) -> Result<Self::TransactionId, Self::Error>;

    /// A tx part of the queue to send transactions in order
    fn get_send_transaction_queue(
        &self,
    ) -> UnboundedSender<TxRequestWithNotifier<Self::TransactionId>> {
        unimplemented!()
    }

    /// Returns fee rate per byte on DA layer.
    async fn get_fee_rate(&self) -> Result<u128, Self::Error>;

    /// Returns the list of SequencerCommitment's (that are not yet included in a block).
    async fn get_pending_sequencer_commitments(
        &self,
        sequencer_da_pub_key: &[u8],
    ) -> Vec<SequencerCommitment>;

    /// Convert a DA layer block to short form header proof.
    fn block_to_short_header_proof(
        block: Self::FilteredBlock,
    ) -> <Self::Spec as DaSpec>::ShortHeaderProof;
}

/// `SlotData` is the subset of a DA layer block which is stored in the rollup's database.
/// At the very least, the rollup needs access to the hashes and headers of all DA layer blocks,
/// but rollup may choose to store partial (or full) block data as well.
pub trait SlotData:
    Serialize + DeserializeOwned + PartialEq + core::fmt::Debug + Clone + Send + Sync
{
    /// The header type for a DA layer block as viewed by the rollup. This need not be identical
    /// to the underlying rollup's header type, but it must be sufficient to reconstruct the block hash.
    ///
    /// For example, most fields of the a Tendermint-based DA chain like Celestia are irrelevant to the rollup.
    /// For these fields, we only ever store their *serialized* representation in memory or on disk. Only a few special
    /// fields like `data_root` are stored in decoded form in the `CelestiaHeader` struct.
    type BlockHeader: BlockHeaderTrait;

    /// The canonical hash of the DA layer block.
    fn hash(&self) -> [u8; 32];
    /// The header of the DA layer block.
    fn header(&self) -> &Self::BlockHeader;
}
