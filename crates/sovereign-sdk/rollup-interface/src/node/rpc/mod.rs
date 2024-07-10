//! The rpc module defines types and traits for querying chain history
//! via an RPC interface.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "native")]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::da::SequencerCommitment;
#[cfg(feature = "native")]
use crate::stf::Event;
use crate::stf::EventKey;
use crate::zk::CumulativeStateDiff;

/// A struct containing enough information to uniquely specify single batch.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotIdAndOffset {
    /// The [`SlotIdentifier`] of the slot containing this batch.
    pub slot_id: SlotIdentifier,
    /// The offset into the slot at which this tx is located.
    /// Index 0 is the first batch in the slot.
    pub offset: u64,
}

/// A struct containing enough information to uniquely specify single transaction.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchIdAndOffset {
    /// The [`BatchIdentifier`] of the batch containing this transaction.
    pub batch_id: BatchIdentifier,
    /// The offset into the batch at which this tx is located.
    /// Index 0 is the first transaction in the batch.
    pub offset: u64,
}

/// A struct containing enough information to uniquely specify single event.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxIdAndOffset {
    /// The [`TxIdentifier`] of the transaction containing this event.
    pub tx_id: TxIdentifier,
    /// The offset into the tx's events at which this event is located.
    /// Index 0 is the first event from this tx.
    pub offset: u64,
}

/// A struct containing enough information to uniquely specify single event.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxIdAndKey {
    /// The [`TxIdentifier`] of the transaction containing this event.
    pub tx_id: TxIdentifier,
    /// The key of the event.
    pub key: EventKey,
}

/// An identifier that specifies a single soft batch
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum SoftBatchIdentifier {
    /// The monotonically increasing number of the soft batch
    Number(u64),
    /// The hex-encoded hash of the soft batch
    Hash(#[serde(with = "utils::rpc_hex")] [u8; 32]),
}

/// An identifier that specifies a single batch
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum BatchIdentifier {
    /// The hex-encoded hash of the batch, as computed by the DA layer.
    Hash(#[serde(with = "utils::rpc_hex")] [u8; 32]),
    /// An offset into a particular slot (i.e. the 3rd batch in slot 5).
    SlotIdAndOffset(SlotIdAndOffset),
    /// The monotonically increasing number of the batch, ordered by the DA layer For example, if the genesis slot
    /// contains 0 batches, slot 1 contains 2 txs, and slot 3 contains 3 txs,
    /// the last batch in block 3 would have number 5. The counter never resets.
    Number(u64),
}

/// An identifier that specifies a single transaction.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum TxIdentifier {
    /// The hex encoded hash of the transaction.
    Hash(#[serde(with = "utils::rpc_hex")] [u8; 32]),
    /// An offset into a particular batch (i.e. the 3rd transaction in batch 5).
    BatchIdAndOffset(BatchIdAndOffset),
    /// The monotonically increasing number of the tx, ordered by the DA layer For example, if genesis
    /// contains 0 txs, batch 1 contains 8 txs, and batch 3 contains 7 txs,
    /// the last tx in batch 3 would have number 15. The counter never resets.
    Number(u64),
}

/// An identifier that specifies a single event.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum EventIdentifier {
    /// An offset into a particular transaction (i.e. the 3rd event in transaction number 5).
    TxIdAndOffset(TxIdAndOffset),
    /// A particular event key from a particular transaction.
    TxIdAndKey(TxIdAndKey),
    /// The monotonically increasing number of the event, ordered by the DA layer For example, if the first tx
    /// contains 7 events, tx 2 contains 11 events, and tx 3 contains 7 txs,
    /// the last event in tx 3 would have number 25. The counter never resets.
    Number(u64),
}

/// An identifier for a group of related events
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum EventGroupIdentifier {
    /// Fetch all events from a particular transaction.
    TxId(TxIdentifier),
    /// Fetch all events (i.e. from all transactions) with a particular key.
    Key(Vec<u8>),
}

/// An identifier that specifies a single slot.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum SlotIdentifier {
    /// The hex encoded hash of the slot (i.e. the da layer's block hash).
    Hash(#[serde(with = "utils::rpc_hex")] [u8; 32]),
    /// The monotonically increasing number of the slot, ordered by the DA layer but starting from 0
    /// at the *rollup's* genesis.
    Number(u64),
}

/// A QueryMode specifies how much information to return in response to an RPC query
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QueryMode {
    /// Returns the parent struct but no details about its children.
    /// For example, a `Compact` "get_slots" response would simply state the range of batch
    /// numbers which occurred in the slot, but not the hashes of the batches themselves.
    Compact,
    /// Returns the parent struct and the hashes of all its children.
    Standard,
    /// Returns the parent struct and all its children, recursively fetching its children
    /// in `Full` mode. For example, a `Full` "get_batch" response would include the `Full`
    /// details of all the transactions in the batch, and those would in turn return the event bodies
    /// which had occurred in those transactions.
    Full,
}

impl Default for QueryMode {
    fn default() -> Self {
        Self::Standard
    }
}

/// The body of a response to a JSON-RPC request for a particular slot.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotResponse<B, Tx> {
    /// The slot number.
    pub number: u64,
    /// The hex encoded slot hash.
    #[serde(with = "utils::rpc_hex")]
    pub hash: [u8; 32],
    /// The range of batches in this slot.
    pub batch_range: core::ops::Range<u64>,
    /// The batches in this slot, if the [`QueryMode`] of the request is not `Compact`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batches: Option<Vec<ItemOrHash<BatchResponse<B, Tx>>>>,
}

/// A type that represents a transaction hash bytes.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(transparent, rename_all = "camelCase")]
pub struct HexTx {
    /// Transaction hash bytes
    #[serde(with = "hex::serde")]
    pub tx: Vec<u8>,
}

impl From<Vec<u8>> for HexTx {
    fn from(tx: Vec<u8>) -> Self {
        Self { tx }
    }
}

/// The response to a JSON-RPC request for a particular soft batch.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftBatchResponse {
    /// The DA height of the soft batch.
    pub da_slot_height: u64,
    /// The DA slothash of the soft batch.
    // TODO: find a way to hex serialize this and then
    // deserialize in `SequencerClient`
    #[serde(with = "hex::serde")]
    pub da_slot_hash: [u8; 32],
    #[serde(with = "hex::serde")]
    /// The DA slot transactions commitment of the soft batch.
    pub da_slot_txs_commitment: [u8; 32],
    /// The hash of the soft batch.
    #[serde(with = "hex::serde")]
    pub hash: [u8; 32],
    /// The transactions in this batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txs: Option<Vec<HexTx>>,
    /// Pre-state root of the soft batch.
    #[serde(with = "hex::serde")]
    pub pre_state_root: Vec<u8>,
    /// Post-state root of the soft batch.
    #[serde(with = "hex::serde")]
    pub post_state_root: Vec<u8>,
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
}

/// The response to a JSON-RPC request for sequencer commitments on a DA Slot.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SequencerCommitmentResponse {
    /// L1 block hash the commitment was on
    pub found_in_l1: u64,
    /// Hex encoded Merkle root of soft confirmation hashes
    #[serde(with = "hex::serde")]
    pub merkle_root: [u8; 32],
    /// Hex encoded Start L2 block's number
    pub l2_start_block_number: u64,
    /// Hex encoded End L2 block's number
    pub l2_end_block_number: u64,
}

/// The rpc response of proof by l1 slot height
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofResponse {
    /// l1 tx id of
    #[serde(with = "hex::serde")]
    pub l1_tx_id: [u8; 32],
    /// Proof
    pub proof: ProofRpcResponse,
    /// State transition
    pub state_transition: StateTransitionRpcResponse,
}

/// The rpc response of proof by l1 slot height
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedProofResponse {
    /// Proof
    pub proof: ProofRpcResponse,
    /// State transition
    pub state_transition: StateTransitionRpcResponse,
}

/// The ZK proof generated by the [`ZkvmHost::run`] method to be served by rpc.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProofRpcResponse {
    /// Only public input was generated.
    #[serde(with = "hex::serde")]
    PublicInput(Vec<u8>),
    /// The serialized ZK proof.
    #[serde(with = "hex::serde")]
    Full(Vec<u8>),
}

/// The state transition response of ledger proof data rpc
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateTransitionRpcResponse {
    /// The state of the rollup before the transition
    #[serde(with = "hex::serde")]
    pub initial_state_root: Vec<u8>,
    /// The state of the rollup after the transition
    #[serde(with = "hex::serde")]
    pub final_state_root: Vec<u8>,
    /// State diff of L2 blocks in the processed sequencer commitments.
    #[serde(
        serialize_with = "custom_serialize_btreemap",
        deserialize_with = "custom_deserialize_btreemap"
    )]
    pub state_diff: CumulativeStateDiff,
    /// The DA slot hash that the sequencer commitments causing this state transition were found in.
    #[serde(with = "hex::serde")]
    pub da_slot_hash: [u8; 32],
    /// Sequencer public key.
    #[serde(with = "hex::serde")]
    pub sequencer_public_key: Vec<u8>,
    /// Sequencer DA public key.
    #[serde(with = "hex::serde")]
    pub sequencer_da_public_key: Vec<u8>,

    /// An additional validity condition for the state transition which needs
    /// to be checked outside of the zkVM circuit. This typically corresponds to
    /// some claim about the DA layer history, such as (X) is a valid block on the DA layer
    #[serde(with = "hex::serde")]
    pub validity_condition: Vec<u8>,
}

/// Custom serialization for BTreeMap
/// Key and value are serialized as hex
/// Value is optional, if None, it is serialized as null
pub fn custom_serialize_btreemap<S>(
    state_diff: &CumulativeStateDiff,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;

    let mut map = serializer.serialize_map(Some(state_diff.len()))?;
    for (key, value) in state_diff.iter() {
        let value = value.as_ref().map(hex::encode);
        map.serialize_entry(&hex::encode(key), &value)?;
    }
    map.end()
}

/// Custom deserialization for BTreeMap
/// Key and value are deserialized from hex
/// Value is optional, if null, it is deserialized as None
/// If the key is not a valid hex string, an error is returned
/// If the value is not a valid hex string or null, an error is returned
pub fn custom_deserialize_btreemap<'de, D>(deserializer: D) -> Result<CumulativeStateDiff, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, MapAccess};

    struct BTreeMapVisitor;

    impl<'de> serde::de::Visitor<'de> for BTreeMapVisitor {
        type Value = CumulativeStateDiff;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("a map")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut btree_map = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, Option<String>>()? {
                let key = hex::decode(&key).map_err(A::Error::custom)?;
                let value = match value {
                    Some(value) => Some(hex::decode(&value).map_err(A::Error::custom)?),
                    None => None,
                };
                btree_map.insert(key, value);
            }
            Ok(btree_map)
        }
    }

    deserializer.deserialize_map(BTreeMapVisitor)
}

/// Converts `SequencerCommitment` to `SequencerCommitmentResponse`
pub fn sequencer_commitment_to_response(
    commitment: SequencerCommitment,
    l1_height: u64,
) -> SequencerCommitmentResponse {
    SequencerCommitmentResponse {
        found_in_l1: l1_height,
        merkle_root: commitment.merkle_root,
        l2_start_block_number: commitment.l2_start_block_number,
        l2_end_block_number: commitment.l2_end_block_number,
    }
}

/// The response to a JSON-RPC request for a particular batch.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchResponse<B, Tx> {
    /// The hex encoded batch hash.
    #[serde(with = "utils::rpc_hex")]
    pub hash: [u8; 32],
    /// The range of transactions in this batch.
    pub tx_range: core::ops::Range<u64>,
    /// The transactions in this batch, if the [`QueryMode`] of the request is not `Compact`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txs: Option<Vec<ItemOrHash<TxResponse<Tx>>>>,
    /// The custom receipt specified by the rollup. This typically contains
    /// information about the outcome of the batch.
    #[serde(skip_serializing)]
    pub phantom_data: PhantomData<B>,
}

/// The response to a JSON-RPC request for a particular transaction.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxResponse<Tx> {
    /// The hex encoded transaction hash.
    #[serde(with = "utils::rpc_hex")]
    pub hash: [u8; 32],
    /// The range of events occurring in this transaction.
    pub event_range: core::ops::Range<u64>,
    /// The transaction body, if stored by the rollup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<HexTx>,
    /// The custom receipt specified by the rollup. This typically contains
    /// information about the outcome of the transaction.
    #[serde(skip_serializing)]
    pub phantom_data: PhantomData<Tx>,
}

/// An RPC response which might contain a full item or just its hash.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum ItemOrHash<T> {
    /// The hex encoded hash of the requested item.
    Hash(#[serde(with = "hex::serde")] [u8; 32]),
    /// The full item body.
    Full(T),
}

/// Statuses for soft confirmation
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum SoftConfirmationStatus {
    /// No confirmation yet, rely on the sequencer
    Trusted,
    /// The soft confirmation has been finalized with a sequencer commitment
    Finalized,
    /// The soft batch has been ZK-proven
    Proven,
}

/// A LedgerRpcProvider provides a way to query the ledger for information about slots, batches, transactions, and events.
#[cfg(feature = "native")]
pub trait LedgerRpcProvider {
    /// Get the latest slot in the ledger.
    fn get_head<B: DeserializeOwned + Clone, T: DeserializeOwned>(
        &self,
        query_mode: QueryMode,
    ) -> Result<Option<SlotResponse<B, T>>, anyhow::Error>;

    /// Get a list of slots by id. The IDs need not be ordered.
    fn get_slots<B: DeserializeOwned, T: DeserializeOwned>(
        &self,
        slot_ids: &[SlotIdentifier],
        query_mode: QueryMode,
    ) -> Result<Vec<Option<SlotResponse<B, T>>>, anyhow::Error>;

    /// Get a list of batches by id. The IDs need not be ordered.
    fn get_batches<B: DeserializeOwned, T: DeserializeOwned>(
        &self,
        batch_ids: &[BatchIdentifier],
        query_mode: QueryMode,
    ) -> Result<Vec<Option<BatchResponse<B, T>>>, anyhow::Error>;

    /// Get a list of soft batches by id. The IDs need not be ordered.
    fn get_soft_batches(
        &self,
        batch_ids: &[SoftBatchIdentifier],
    ) -> Result<Vec<Option<SoftBatchResponse>>, anyhow::Error>;

    /// Get soft batch
    fn get_soft_batch(
        &self,
        batch_id: &SoftBatchIdentifier,
    ) -> Result<Option<SoftBatchResponse>, anyhow::Error>;

    /// Get a list of transactions by id. The IDs need not be ordered.
    fn get_transactions<T: DeserializeOwned>(
        &self,
        tx_ids: &[TxIdentifier],
        query_mode: QueryMode,
    ) -> Result<Vec<Option<TxResponse<T>>>, anyhow::Error>;

    /// Get events by id. The IDs need not be ordered.
    fn get_events(
        &self,
        event_ids: &[EventIdentifier],
    ) -> Result<Vec<Option<Event>>, anyhow::Error>;

    /// Get a single slot by hash.
    fn get_slot_by_hash<B: DeserializeOwned, T: DeserializeOwned>(
        &self,
        hash: &[u8; 32],
        query_mode: QueryMode,
    ) -> Result<Option<SlotResponse<B, T>>, anyhow::Error>;

    /// Get a single soft batch by hash.
    fn get_soft_batch_by_hash<T: DeserializeOwned>(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<SoftBatchResponse>, anyhow::Error>;

    /// Get a single batch by hash.
    fn get_batch_by_hash<B: DeserializeOwned, T: DeserializeOwned>(
        &self,
        hash: &[u8; 32],
        query_mode: QueryMode,
    ) -> Result<Option<BatchResponse<B, T>>, anyhow::Error>;

    /// Get a single transaction by hash.
    fn get_tx_by_hash<T: DeserializeOwned>(
        &self,
        hash: &[u8; 32],
        query_mode: QueryMode,
    ) -> Result<Option<TxResponse<T>>, anyhow::Error>;

    /// Get a single slot by number.
    fn get_slot_by_number<B: DeserializeOwned, T: DeserializeOwned>(
        &self,
        number: u64,
        query_mode: QueryMode,
    ) -> Result<Option<SlotResponse<B, T>>, anyhow::Error>;

    /// Get a single soft batch by number.
    fn get_soft_batch_by_number<T: DeserializeOwned>(
        &self,
        number: u64,
    ) -> Result<Option<SoftBatchResponse>, anyhow::Error>;

    /// Get a single batch by number.
    fn get_batch_by_number<B: DeserializeOwned, T: DeserializeOwned>(
        &self,
        number: u64,
        query_mode: QueryMode,
    ) -> Result<Option<BatchResponse<B, T>>, anyhow::Error>;

    /// Get a single event by number.
    fn get_event_by_number(&self, number: u64) -> Result<Option<Event>, anyhow::Error>;

    /// Get a single tx by number.
    fn get_tx_by_number<T: DeserializeOwned>(
        &self,
        number: u64,
        query_mode: QueryMode,
    ) -> Result<Option<TxResponse<T>>, anyhow::Error>;

    /// Get a range of slots. This query is the most efficient way to
    /// fetch large numbers of slots, since it allows for easy batching of
    /// db queries for adjacent items.
    fn get_slots_range<B: DeserializeOwned, T: DeserializeOwned>(
        &self,
        start: u64,
        end: u64,
        query_mode: QueryMode,
    ) -> Result<Vec<Option<SlotResponse<B, T>>>, anyhow::Error>;

    /// Get a range of batches. This query is the most efficient way to
    /// fetch large numbers of batches, since it allows for easy batching of
    /// db queries for adjacent items.
    fn get_batches_range<B: DeserializeOwned, T: DeserializeOwned>(
        &self,
        start: u64,
        end: u64,
        query_mode: QueryMode,
    ) -> Result<Vec<Option<BatchResponse<B, T>>>, anyhow::Error>;

    /// Get a range of soft batches.
    fn get_soft_batches_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Option<SoftBatchResponse>>, anyhow::Error>;

    /// Get a range of batches. This query is the most efficient way to
    /// fetch large numbers of transactions, since it allows for easy batching of
    /// db queries for adjacent items.
    fn get_transactions_range<T: DeserializeOwned>(
        &self,
        start: u64,
        end: u64,
        query_mode: QueryMode,
    ) -> Result<Vec<Option<TxResponse<T>>>, anyhow::Error>;

    /// Takes an L2 Height and and returns the soft confirmation status of the soft batch
    fn get_soft_confirmation_status(
        &self,
        soft_batch_receipt: u64,
    ) -> Result<SoftConfirmationStatus, anyhow::Error>;

    /// (Prover) returns the last scanned L1 height (for sequencer commitments)
    fn get_prover_last_scanned_l1_height(&self) -> Result<u64, anyhow::Error>;

    /// Returns the slot number of a given hash
    fn get_slot_number_by_hash(&self, hash: [u8; 32]) -> Result<Option<u64>, anyhow::Error>;

    /// Takes an L1 height and and returns all the sequencer commitments on the slot
    fn get_sequencer_commitments_on_slot_by_number(
        &self,
        height: u64,
    ) -> Result<Option<Vec<SequencerCommitmentResponse>>, anyhow::Error>;

    /// Get a notification each time a slot is processed
    fn subscribe_slots(&self) -> Result<tokio::sync::broadcast::Receiver<u64>, anyhow::Error>;

    /// Get proof by l1 height
    fn get_proof_data_by_l1_height(
        &self,
        height: u64,
    ) -> Result<Option<ProofResponse>, anyhow::Error>;

    /// Get verified proof by l1 height
    fn get_verified_proof_data_by_l1_height(
        &self,
        height: u64,
    ) -> Result<Option<Vec<VerifiedProofResponse>>, anyhow::Error>;

    /// Get head soft batch
    fn get_head_soft_batch(&self) -> Result<Option<SoftBatchResponse>, anyhow::Error>;

    /// Get head soft batch height
    fn get_head_soft_batch_height(&self) -> Result<u64, anyhow::Error>;
}

/// JSON-RPC -related utilities. Occasionally useful but unimportant for most
/// use cases.
pub mod utils {
    /// Serialization and deserialization logic for `0x`-prefixed hex strings.
    pub mod rpc_hex {
        extern crate alloc;

        use alloc::format;
        use alloc::string::String;
        use core::fmt;
        use core::marker::PhantomData;

        use hex::{FromHex, ToHex};
        use serde::de::{Error, Visitor};
        use serde::{Deserializer, Serializer};

        /// Serializes `data` as hex string using lowercase characters and prefixing with '0x'.
        ///
        /// Lowercase characters are used (e.g. `f9b4ca`). The resulting string's length
        /// is always even, each byte in data is always encoded using two hex digits.
        /// Thus, the resulting string contains exactly twice as many bytes as the input
        /// data.
        pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: ToHex,
        {
            let formatted_string = format!("0x{}", data.encode_hex::<String>());
            serializer.serialize_str(&formatted_string)
        }

        /// Deserializes a hex string into raw bytes.
        ///
        /// Both, upper and lower case characters are valid in the input string and can
        /// even be mixed (e.g. `f9b4ca`, `F9B4CA` and `f9B4Ca` are all valid strings).
        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where
            D: Deserializer<'de>,
            T: FromHex,
            <T as FromHex>::Error: fmt::Display,
        {
            struct HexStrVisitor<T>(PhantomData<T>);

            impl<'de, T> Visitor<'de> for HexStrVisitor<T>
            where
                T: FromHex,
                <T as FromHex>::Error: fmt::Display,
            {
                type Value = T;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a hex encoded string")
                }

                fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
                where
                    E: Error,
                {
                    let data = data.trim_start_matches("0x");
                    FromHex::from_hex(data).map_err(Error::custom)
                }

                fn visit_borrowed_str<E>(self, data: &'de str) -> Result<Self::Value, E>
                where
                    E: Error,
                {
                    let data = data.trim_start_matches("0x");
                    FromHex::from_hex(data).map_err(Error::custom)
                }
            }

            deserializer.deserialize_str(HexStrVisitor(PhantomData))
        }
    }
}

#[cfg(test)]
mod rpc_hex_tests {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct TestStruct {
        #[serde(with = "super::utils::rpc_hex")]
        data: Vec<u8>,
    }

    #[test]
    fn test_roundtrip() {
        let test_data = TestStruct {
            data: vec![0x01, 0x02, 0x03, 0x04],
        };

        let serialized = serde_json::to_string(&test_data).unwrap();
        assert!(serialized.contains("0x01020304"));
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, test_data)
    }

    #[test]
    fn test_accepts_hex_without_0x_prefix() {
        let test_data = TestStruct {
            data: vec![0x01, 0x02, 0x03, 0x04],
        };

        let deserialized: TestStruct = serde_json::from_str(r#"{"data": "01020304"}"#).unwrap();
        assert_eq!(deserialized, test_data)
    }
}
