//! A [`jsonrpsee`] client for interacting with the Sovereign SDK ledger
//! JSON-RPC API.
//!
//! See [`RpcClient`].

use jsonrpsee::proc_macros::rpc;
use sov_rollup_interface::rpc::{
    ProofResponse, SequencerCommitmentResponse, SoftConfirmationResponse, SoftConfirmationStatus,
    VerifiedProofResponse,
};

use crate::HexHash;

/// A [`jsonrpsee`] trait for interacting with the ledger JSON-RPC API.
///
/// Client and server implementations are automatically generated by
/// [`jsonrpsee`], see [`RpcClient`] and [`RpcServer`].
///
/// For more information about the specific methods, see the
/// [`sov_rollup_interface::rpc`] module.
#[rpc(client, namespace = "ledger")]
pub trait Rpc {
    /// Gets a single soft confirmation by number.
    #[method(name = "getSoftConfirmationByNumber")]
    async fn get_soft_confirmation_by_number(
        &self,
        number: u64,
    ) -> RpcResult<Option<SoftConfirmationResponse>>;

    /// Gets a single soft confirmation by hash.
    #[method(name = "getSoftConfirmationByHash")]
    async fn get_soft_confirmation_by_hash(
        &self,
        hash: HexHash,
    ) -> RpcResult<Option<SoftConfirmationResponse>>;

    /// Gets all soft confirmations with numbers `range.start` to `range.end`.
    #[method(name = "getSoftConfirmationRange")]
    async fn get_soft_confirmation_range(
        &self,
        range: (u64, u64),
    ) -> RpcResult<Vec<Option<SoftConfirmationResponse>>>;

    /// Gets a single event by number.
    #[method(name = "getSoftConfirmationStatus")]
    async fn get_soft_confirmation_status(
        &self,
        soft_confirmation_receipt: u64,
    ) -> RpcResult<SoftConfirmationStatus>;

    /// Gets the commitments in the DA slot with the given height.
    #[method(name = "getSequencerCommitmentsOnSlotByNumber")]
    async fn get_sequencer_commitments_on_slot_by_number(
        &self,
        height: u64,
    ) -> RpcResult<Option<Vec<SequencerCommitmentResponse>>>;

    /// Gets the commitments in the DA slot with the given hash.
    #[method(name = "getSequencerCommitmentsOnSlotByHash")]
    async fn get_sequencer_commitments_on_slot_by_hash(
        &self,
        hash: [u8; 32],
    ) -> RpcResult<Option<Vec<SequencerCommitmentResponse>>>;

    /// Gets proof by slot height.
    #[method(name = "getProofsBySlotHeight")]
    async fn get_proofs_by_slot_height(&self, height: u64) -> RpcResult<Option<ProofResponse>>;

    /// Gets proof by slot hash.
    #[method(name = "getProofsBySlotHash")]
    async fn get_proofs_by_slot_hash(&self, hash: [u8; 32]) -> RpcResult<Option<ProofResponse>>;

    /// Gets the height pf most recent committed soft confirmation.
    #[method(name = "getHeadSoftConfirmation")]
    async fn get_head_soft_confirmation(&self) -> RpcResult<Option<SoftConfirmationResponse>>;

    /// Gets the height pf most recent committed soft confirmation.
    #[method(name = "getHeadSoftConfirmationHeight")]
    async fn get_head_soft_confirmation_height(&self) -> RpcResult<u64>;

    /// Gets verified proofs by slot height
    #[method(name = "getVerifiedProofsBySlotHeight")]
    async fn get_verified_proofs_by_slot_height(
        &self,
        height: u64,
    ) -> RpcResult<Option<Vec<VerifiedProofResponse>>>;

    /// Gets last verified proog
    #[method(name = "getLastVerifiedProof")]
    async fn get_last_verified_proof(&self) -> RpcResult<Option<VerifiedProofResponse>>;
}
