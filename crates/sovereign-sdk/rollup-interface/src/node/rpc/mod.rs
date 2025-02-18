//! The rpc module defines types and traits for querying chain history
//! via an RPC interface.

use std::collections::BTreeMap;

use alloy_primitives::{U32, U64, U8};
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

use crate::da::SequencerCommitment;
use crate::mmr::MMRGuest;
use crate::soft_confirmation::{L2Block, L2Header, SignedL2Header};
use crate::zk::batch_proof::output::CumulativeStateDiff;
use crate::zk::light_client_proof::output::BatchProofInfo;
use crate::RefCount;

/// A struct containing enough information to uniquely specify single batch.

/// An identifier that specifies a single soft confirmation
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum SoftConfirmationIdentifier {
    /// The monotonically increasing number of the soft confirmation
    Number(u64),
    /// The hex-encoded hash of the soft confirmation
    Hash(#[serde(with = "utils::rpc_hex")] [u8; 32]),
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

impl<'txs, Tx> TryFrom<SoftConfirmationResponse> for L2Block<'txs, Tx>
where
    Tx: Clone + BorshDeserialize + BorshSerialize,
{
    type Error = borsh::io::Error;
    fn try_from(val: SoftConfirmationResponse) -> Result<Self, Self::Error> {
        let parsed_txs = val
            .txs
            .iter()
            .flatten()
            .map(|tx| {
                let body = &tx.tx;
                borsh::from_slice::<Tx>(body)
            })
            .collect::<Result<Vec<_>, Self::Error>>()?;

        let blobs = val
            .txs
            .unwrap_or_default()
            .into_iter()
            .map(|tx| tx.tx)
            .collect::<Vec<_>>();

        let header = L2Header::new(
            val.l2_height,
            val.da_slot_height,
            val.da_slot_hash,
            val.da_slot_txs_commitment,
            val.prev_hash,
            val.state_root,
            val.l1_fee_rate,
            val.tx_merkle_root,
            val.timestamp,
        );
        let signed_header = SignedL2Header::new(
            header,
            val.hash,
            val.soft_confirmation_signature,
            val.pub_key,
        );

        let res = L2Block::new(
            signed_header,
            parsed_txs.into(),
            blobs.into(),
            val.deposit_data.into_iter().map(|tx| tx.tx).collect(),
        );
        Ok(res)
    }
}

/// The response to a JSON-RPC request for sequencer commitments on a DA Slot.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SequencerCommitmentResponse {
    /// L1 block height the commitment was on
    pub l1_height: U64,
    /// Hex encoded Merkle root of soft confirmation hashes
    #[serde(with = "utils::rpc_hex")]
    pub merkle_root: [u8; 32],
    /// Hex encoded Start L2 block's number
    pub l2_start_block_number: U64,
    /// Hex encoded End L2 block's number
    pub l2_end_block_number: U64,
}

/// Latest da state to verify and apply da block changes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatestDaStateRpcResponse {
    /// Proved DA block's header hash
    /// This is used to compare the previous DA block hash with first batch proof's DA block hash
    #[serde(with = "hex::serde")] // without 0x prefix
    pub block_hash: [u8; 32],
    /// Height of the blockchain
    pub block_height: U64,
    /// Total work done in the DA blockchain
    #[serde(with = "utils::rpc_hex")]
    pub total_work: [u8; 32],
    /// Current target bits of DA
    pub current_target_bits: U32,
    /// The time of the first block in the current epoch (the difficulty adjustment timestamp)
    pub epoch_start_time: U32,
    /// The UNIX timestamps in seconds of the previous 11 blocks
    pub prev_11_timestamps: [U32; 11],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
/// Activation height and method id
pub struct BatchProofMethodIdRpcResponse {
    /// Activation height
    pub height: U64,
    #[serde(with = "utils::rpc_hex")]
    /// Method id
    pub method_id: Digest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Hex serializable BatchProofInfo
pub struct BatchProofInfoRpcResponse {
    /// Initial state root of the batch proof
    #[serde(with = "utils::rpc_hex")]
    pub initial_state_root: [u8; 32],
    /// Final state root of the batch proof
    #[serde(with = "utils::rpc_hex")]
    pub final_state_root: [u8; 32],
    /// The last processed l2 height in the batch proof
    pub last_l2_height: U64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
/// Hex serializable Root
pub struct Root(#[serde(with = "utils::rpc_hex")] [u8; 32]);

/// Hex serializable MMRGuest
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MMRGuestRpcResponse {
    /// Subroots of the MMR
    pub subroots: Vec<Root>,
    /// Size of the MMR
    pub size: U64,
}

impl From<MMRGuest> for MMRGuestRpcResponse {
    fn from(mmr: MMRGuest) -> Self {
        Self {
            subroots: mmr.subroots.into_iter().map(Root).collect(),
            size: U64::from(mmr.size),
        }
    }
}

impl From<BatchProofInfo> for BatchProofInfoRpcResponse {
    fn from(info: BatchProofInfo) -> Self {
        Self {
            initial_state_root: info.initial_state_root,
            final_state_root: info.final_state_root,
            last_l2_height: U64::from(info.last_l2_height),
        }
    }
}

/// The output of a light client proof
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LightClientProofOutputRpcResponse {
    /// State root of the node after the light client proof
    #[serde(with = "utils::rpc_hex")]
    pub state_root: [u8; 32],
    /// The method id of the light client proof
    /// This is used to compare the previous light client proof method id with the input (current) method id
    #[serde(with = "utils::rpc_hex")]
    pub light_client_proof_method_id: Digest,
    /// Latest DA state after proof
    pub latest_da_state: LatestDaStateRpcResponse,
    /// Batch proof info from current or previous light client proofs that were not changed and unable to update the state root yet
    pub unchained_batch_proofs_info: Vec<BatchProofInfoRpcResponse>,
    /// Last l2 height the light client proof verifies
    pub last_l2_height: U64,
    /// L2 activation height of the fork and the Method ids of the batch proofs that were verified in the light client proof
    pub batch_proof_method_ids: Vec<BatchProofMethodIdRpcResponse>,
    /// A map from tx hash to chunk data.
    /// MMRGuest is an impl. MMR, which only needs to hold considerably small amount of data.
    /// like 32 hashes and some u64
    pub mmr_guest: MMRGuestRpcResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The response to a JSON-RPC request for a light client proof
pub struct LightClientProofResponse {
    /// The proof
    #[serde(with = "faster_hex")]
    pub proof: ProofRpcResponse,
    /// The output of the light client proof circuit
    pub light_client_proof_output: LightClientProofOutputRpcResponse,
}

/// The rpc response of proof by l1 slot height
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchProofResponse {
    /// l1 tx id of
    #[serde(with = "hex::serde")] // without 0x prefix
    pub l1_tx_id: [u8; 32],
    /// Proof
    #[serde(with = "faster_hex")]
    pub proof: ProofRpcResponse,
    /// State transition
    pub proof_output: BatchProofOutputRpcResponse,
}

/// The rpc response of proof by l1 slot height
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedBatchProofResponse {
    /// Proof
    #[serde(with = "faster_hex")]
    pub proof: ProofRpcResponse,
    /// State transition
    pub proof_output: BatchProofOutputRpcResponse,
}

/// The rpc response of the last verified proof
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastVerifiedBatchProofResponse {
    /// Proof data
    pub proof: VerifiedBatchProofResponse,
    /// L1 height of the proof
    pub l1_height: U64,
}

/// The ZK proof generated by the [`ZkvmHost::run`] method to be served by rpc.
pub type ProofRpcResponse = Vec<u8>;

/// Workaround to serialize [u8; 32] with rpc_hex when the hash is optinal
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct SerializableHash(#[serde(with = "utils::rpc_hex")] pub [u8; 32]);

/// The state transition response of ledger proof data rpc
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchProofOutputRpcResponse {
    /// The state of the rollup before the transition
    #[serde(with = "faster_hex")]
    pub initial_state_root: Vec<u8>,
    /// The state of the rollup after the transition
    #[serde(with = "faster_hex")]
    pub final_state_root: Vec<u8>,
    /// The hash of the last soft confirmation before the state transition
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_soft_confirmation_hash: Option<SerializableHash>,
    /// The hash of the last soft confirmation in the state transition
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_soft_confirmation_hash: Option<SerializableHash>,
    /// State diff of L2 blocks in the processed sequencer commitments.
    #[serde(
        serialize_with = "custom_serialize_btreemap",
        deserialize_with = "custom_deserialize_btreemap"
    )]
    pub state_diff: CumulativeStateDiff,
    /// The DA slot hash that the sequencer commitments causing this state transition were found in.
    #[serde(skip_serializing_if = "Option::is_none")] // without 0x prefix
    pub da_slot_hash: Option<SerializableHash>,
    /// The range of sequencer commitments in the DA slot that were processed.
    /// The range is inclusive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequencer_commitments_range: Option<(U32, U32)>,
    /// Sequencer public key.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    #[serde(with = "faster_hex")]
    pub sequencer_public_key: Vec<u8>,
    /// Sequencer DA public key.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    #[serde(with = "hex::serde")] // without 0x prefix
    pub sequencer_da_public_key: Vec<u8>,
    /// Pre-proven commitments L2 ranges which also exist in the current L1 `da_data`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preproven_commitments: Option<Vec<usize>>,
    /// Last active spec id in the proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_active_spec_id: Option<U8>,
    /// The last processed l2 height in the processed sequencer commitments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_l2_height: Option<U64>,
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
        let key = format!("0x{}", faster_hex::hex_string(key));
        let value = value
            .as_ref()
            .map(|v| format!("0x{}", faster_hex::hex_string(v)));
        map.serialize_entry(&key, &value)?;
    }
    map.end()
}

/// Helper function to use faster_hex::hex_decode, value must not contain 0x and the len should be even
fn faster_hex_decode(value: &str) -> Result<Vec<u8>, faster_hex::Error> {
    let src = value.as_bytes();
    let mut dst = vec![0; src.len() / 2];
    faster_hex::hex_decode(src, &mut dst)?;
    Ok(dst)
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
                let key = key.trim_start_matches("0x");
                let key = faster_hex_decode(key).map_err(A::Error::custom)?;

                let value = match value {
                    Some(value) => {
                        let value = value.trim_start_matches("0x");
                        Some(faster_hex_decode(value).map_err(A::Error::custom)?)
                    }
                    None => None,
                };
                btree_map.insert(RefCount::from(key), value.map(RefCount::from));
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
        l1_height: U64::from(l1_height),
        merkle_root: commitment.merkle_root,
        l2_start_block_number: U64::from(commitment.l2_start_block_number),
        l2_end_block_number: U64::from(commitment.l2_end_block_number),
    }
}

/// An RPC response which might contain a full item or just its hash.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum ItemOrHash<T> {
    /// The hex encoded hash of the requested item.
    Hash(#[serde(with = "utils::rpc_hex")] [u8; 32]),
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
    /// The soft confirmation has been ZK-proven
    Proven,
}

/// A LedgerRpcProvider provides a way to query the ledger for information about slots, batches, transactions, and events.
#[cfg(feature = "native")]
pub trait LedgerRpcProvider {
    /// Get a list of soft confirmations by id. The IDs need not be ordered.
    fn get_soft_confirmations(
        &self,
        batch_ids: &[SoftConfirmationIdentifier],
    ) -> Result<Vec<Option<SoftConfirmationResponse>>, anyhow::Error>;

    /// Get soft confirmation
    fn get_soft_confirmation(
        &self,
        batch_id: &SoftConfirmationIdentifier,
    ) -> Result<Option<SoftConfirmationResponse>, anyhow::Error>;

    /// Get a single soft confirmation by hash.
    fn get_soft_confirmation_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<SoftConfirmationResponse>, anyhow::Error>;

    /// Get a single soft confirmation by number.
    fn get_soft_confirmation_by_number(
        &self,
        number: u64,
    ) -> Result<Option<SoftConfirmationResponse>, anyhow::Error>;

    /// Get a range of soft confirmations.
    fn get_soft_confirmations_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Option<SoftConfirmationResponse>>, anyhow::Error>;

    /// Takes an L2 Height and and returns the soft confirmation status of the soft confirmation
    fn get_soft_confirmation_status(
        &self,
        soft_confirmation_receipt: u64,
    ) -> Result<SoftConfirmationStatus, anyhow::Error>;

    /// Returns the L2 genesis state root
    fn get_l2_genesis_state_root(&self) -> Result<Option<Vec<u8>>, anyhow::Error>;

    /// Returns the last scanned L1 height (for sequencer commitments)
    fn get_last_scanned_l1_height(&self) -> Result<u64, anyhow::Error>;

    /// Returns the slot number of a given hash
    fn get_slot_number_by_hash(&self, hash: [u8; 32]) -> Result<Option<u64>, anyhow::Error>;

    /// Takes an L1 height and and returns all the sequencer commitments on the slot
    fn get_sequencer_commitments_on_slot_by_number(
        &self,
        height: u64,
    ) -> Result<Option<Vec<SequencerCommitmentResponse>>, anyhow::Error>;

    /// Get batch proof by l1 height
    fn get_batch_proof_data_by_l1_height(
        &self,
        height: u64,
    ) -> Result<Option<Vec<BatchProofResponse>>, anyhow::Error>;

    /// Get verified proof by l1 height
    fn get_verified_proof_data_by_l1_height(
        &self,
        height: u64,
    ) -> Result<Option<Vec<VerifiedBatchProofResponse>>, anyhow::Error>;

    /// Get last verified proof
    fn get_last_verified_batch_proof(
        &self,
    ) -> Result<Option<LastVerifiedBatchProofResponse>, anyhow::Error>;

    /// Get head soft confirmation
    fn get_head_soft_confirmation(&self)
        -> Result<Option<SoftConfirmationResponse>, anyhow::Error>;

    /// Get head soft confirmation height
    fn get_head_soft_confirmation_height(&self) -> Result<u64, anyhow::Error>;
}

/// JSON-RPC -related utilities. Occasionally useful but unimportant for most
/// use cases.
pub mod utils {
    /// Serialization and deserialization logic for `0x`-prefixed hex strings.
    pub mod rpc_hex {
        use std::fmt;
        use std::marker::PhantomData;

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
