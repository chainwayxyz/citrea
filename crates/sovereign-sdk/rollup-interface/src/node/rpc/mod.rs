//! The rpc module defines types and traits for querying chain history
//! via an RPC interface.

use std::collections::BTreeMap;

use alloy_primitives::{U32, U64};
use block::L2BlockResponse;
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::da::SequencerCommitment;
use crate::mmr::MMRGuest;
use crate::zk::batch_proof::output::CumulativeStateDiff;
use crate::zk::light_client_proof::output::VerifiedStateTransitionForSequencerCommitmentIndex;
use crate::RefCount;

/// L2 Block response
pub mod block;

/// An identifier that specifies a single l2 block
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum L2BlockIdentifier {
    /// The monotonically increasing number of the l2 block
    Number(u64),
    /// The hex-encoded hash of the l2 block
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

/// The response to a JSON-RPC request for sequencer commitments on a DA Slot.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SequencerCommitmentResponse {
    /// Hex encoded Merkle root of l2 block hashes
    #[serde(with = "utils::rpc_hex")]
    pub merkle_root: [u8; 32],
    /// Hex encoded index - absolute order
    pub index: U32,
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

impl From<VerifiedStateTransitionForSequencerCommitmentIndex> for BatchProofInfoRpcResponse {
    fn from(info: VerifiedStateTransitionForSequencerCommitmentIndex) -> Self {
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
    pub l2_state_root: [u8; 32],
    /// LCP JMT state root
    #[serde(with = "utils::rpc_hex")]
    pub lcp_state_root: [u8; 32],
    /// The method id of the light client proof
    /// This is used to compare the previous light client proof method id with the input (current) method id
    #[serde(with = "utils::rpc_hex")]
    pub light_client_proof_method_id: Digest,
    /// Latest DA state after proof
    pub latest_da_state: LatestDaStateRpcResponse,
    /// Last l2 height the light client proof verifies
    pub last_l2_height: U64,
    /// The last sequencer commitment index of the last fully stitched and verified batch proof
    pub last_sequencer_commitment_index: U32,
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

/// The response to JSON-RPC request for querying proving job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRpcResponse {
    /// Job id
    pub id: Uuid,
    /// Commitments being proven in the job
    pub commitments: Vec<SequencerCommitmentResponse>,
    /// Proof result of the job. If proof is None, job still continues,
    /// and if it is Some but l1_tx_id is 0-value, it is being submitted to L1.
    pub proof: Option<BatchProofResponse>,
}

/// Parameter type used in set commitments rpc.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SequencerCommitmentRpcParam {
    /// Merkle root of the commitment
    #[serde(with = "utils::rpc_hex")]
    pub merkle_root: [u8; 32],
    /// Index of the commitment
    pub index: U32,
    /// L2 end block number of the commitment
    pub l2_end_block_number: U64,
    /// L1 height of the commitment
    pub l1_height: U64,
}

/// The rpc response of proof by l1 slot height
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchProofResponse {
    /// l1 tx id of
    #[serde(with = "utils::option_hex_array32")]
    pub l1_tx_id: Option<[u8; 32]>,
    /// Proof
    #[serde(with = "faster_hex")]
    pub proof: ProofRpcResponse,
    /// State transition
    pub proof_output: BatchProofOutputRpcResponse,
}

/// The rpc response of proof by l1 slot height
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedBatchProofResponse {
    /// Proof
    #[serde(with = "faster_hex")]
    pub proof: ProofRpcResponse,
    /// State transition
    pub proof_output: BatchProofOutputRpcResponse,
}

/// The rpc response of the last verified proof
#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct SerializableHash(#[serde(with = "faster_hex")] pub Vec<u8>);

/// The state transition response of ledger proof data rpc
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchProofOutputRpcResponse {
    /// All the state roots of commitments from initial state (previous commitments state root) to the last sequencer commitment
    pub state_roots: Vec<SerializableHash>,
    /// The hash of the last l2 block in the state transition
    #[serde(with = "faster_hex")]
    pub final_l2_block_hash: Vec<u8>,
    /// State diff of L2 blocks in the processed sequencer commitments.
    #[serde(
        serialize_with = "custom_serialize_btreemap",
        deserialize_with = "custom_deserialize_btreemap"
    )]
    pub state_diff: CumulativeStateDiff,
    /// The last processed l2 height in the processed sequencer commitments.
    pub last_l2_height: U64,
    /// The range of sequencer commitments in the DA slot that were processed.
    /// The range is inclusive.
    pub sequencer_commitment_index_range: (U32, U32),
    /// Hashes inside sequencer commitments that were processed.
    pub sequencer_commitment_hashes: Vec<SerializableHash>,
    /// L1 hashes that were added to the Bitcoin light client contract
    #[serde(with = "faster_hex")]
    pub last_l1_hash_on_bitcoin_light_client_contract: Vec<u8>,
    /// The index of the previous commitment that was given as input in the batch proof
    pub previous_commitment_index: Option<U32>,
    /// The hash of the previous commitment that was given as input in the batch proof
    pub previous_commitment_hash: Option<SerializableHash>,
}

impl BatchProofOutputRpcResponse {
    /// Get final state root of batch proof
    pub fn final_state_root(&self) -> [u8; 32] {
        self.state_roots
            .last()
            .unwrap()
            .0
            .clone()
            .try_into()
            .unwrap()
    }

    /// Get initial state root of batch proof
    pub fn initial_state_root(&self) -> [u8; 32] {
        self.state_roots
            .first()
            .unwrap()
            .0
            .clone()
            .try_into()
            .unwrap()
    }
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
) -> SequencerCommitmentResponse {
    SequencerCommitmentResponse {
        merkle_root: commitment.merkle_root,
        index: U32::from(commitment.index),
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

/// A LedgerRpcProvider provides a way to query the ledger for information about slots, batches, transactions, and events.
#[cfg(feature = "native")]
pub trait LedgerRpcProvider {
    /// Get a list of l2 blocks by id. The IDs need not be ordered.
    fn get_l2_blocks(
        &self,
        batch_ids: &[L2BlockIdentifier],
    ) -> Result<Vec<Option<L2BlockResponse>>, anyhow::Error>;

    /// Get l2 block
    fn get_l2_block(
        &self,
        batch_id: &L2BlockIdentifier,
    ) -> Result<Option<L2BlockResponse>, anyhow::Error>;

    /// Get a single l2 block by hash.
    fn get_l2_block_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<L2BlockResponse>, anyhow::Error>;

    /// Get a single l2 block by number.
    fn get_l2_block_by_number(&self, number: u64)
        -> Result<Option<L2BlockResponse>, anyhow::Error>;

    /// Get a range of l2 blocks.
    fn get_l2_blocks_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Option<L2BlockResponse>>, anyhow::Error>;

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

    /// Takes an index and returns the commitment in the ledger db saved with that index
    fn get_sequencer_commitment_by_index(
        &self,
        index: u32,
    ) -> Result<Option<SequencerCommitmentResponse>, anyhow::Error>;

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

    /// Get head l2 block
    fn get_head_l2_block(&self) -> Result<Option<L2BlockResponse>, anyhow::Error>;

    /// Get head l2 block height
    fn get_head_l2_block_height(&self) -> Result<u64, anyhow::Error>;
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

    /// Serde module for serializing Option wrapped [u8; 32] as hex string
    pub mod option_hex_array32 {
        use hex;
        use serde::{Deserialize, Deserializer, Serializer};

        /// Serialize Option<[[u8; 32]]> as hex string
        pub fn serialize<S>(val: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match val {
                Some(arr) => serializer.serialize_str(&hex::encode(arr)),
                None => serializer.serialize_none(),
            }
        }

        /// Deserialize Option<[[u8; 32]]> from hex string
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt = Option::<String>::deserialize(deserializer)?;
            match opt {
                Some(hex_str) => {
                    let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                    if bytes.len() != 32 {
                        return Err(serde::de::Error::custom("Expected 32-byte hex string"));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Ok(Some(arr))
                }
                None => Ok(None),
            }
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
