use serde::{Deserialize, Serialize};
use sov_rollup_interface::rpc::HexTx;

/// The response to a JSON-RPC request for a particular soft confirmation.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftConfirmationResponse {
    /// The L2 height of the soft confirmation.
    pub l2_height: u64,
    /// The DA height of the soft confirmation.
    pub da_slot_height: u64,
    /// The DA slothash of the soft confirmation.
    // TODO: find a way to hex serialize this and then
    // deserialize in `SequencerClient`
    #[serde(with = "hex::serde")]
    pub da_slot_hash: [u8; 32],
    #[serde(with = "hex::serde")]
    /// The DA slot transactions commitment of the soft confirmation.
    pub da_slot_txs_commitment: [u8; 32],
    /// The hash of the soft confirmation.
    #[serde(with = "hex::serde")]
    pub hash: [u8; 32],
    /// The hash of the previous soft confirmation.
    #[serde(with = "hex::serde")]
    pub prev_hash: [u8; 32],
    /// The transactions in this batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txs: Option<Vec<HexTx>>,
    /// State root of the soft confirmation.
    #[serde(with = "hex::serde")]
    pub state_root: [u8; 32],
    /// Signature of the batch
    #[serde(with = "hex::serde")]
    pub soft_confirmation_signature: Vec<u8>,
    /// Public key of the signer
    #[serde(with = "hex::serde")]
    pub pub_key: Vec<u8>,
    /// Deposit data from the L1 chain
    pub deposit_data: Vec<HexTx>, // Vec<u8> wrapper around deposit data
    /// Base layer fee rate sats/wei etc. per byte.
    pub l1_fee_rate: u128,
    /// Sequencer's block timestamp.
    pub timestamp: u64,
    /// Tx merkle root.
    pub tx_merkle_root: [u8; 32],
}

/// A Transaction object that is compatible with the module-system/sov-default-stf.
#[derive(
    Debug, PartialEq, Eq, Clone, borsh::BorshDeserialize, borsh::BorshSerialize, serde::Serialize,
)]
pub struct PreFork2Transaction<C: sov_modules_api::Context> {
    pub signature: C::Signature,
    pub pub_key: C::PublicKey,
    pub runtime_msg: Vec<u8>,
    pub chain_id: u64,
    pub nonce: u64,
}
