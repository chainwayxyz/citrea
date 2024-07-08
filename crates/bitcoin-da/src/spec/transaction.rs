// pub use bitcoin::Transaction;
pub type Transaction = OurTransaction;

use bitcoin::Transaction as BitTransaction;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, PartialEq, Eq, Debug, Hash, BorshDeserialize, BorshSerialize, Serialize, Deserialize,
)]
pub struct OurTransaction {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
    pub version: Version,
    /// Block height or timestamp.
    pub lock_time: LockTime,
    /// List of transaction inputs.
    pub input: Vec<TxIn>,
    /// List of transaction outputs.
    pub output: Vec<TxOut>,
}

impl OurTransaction {
    /// Creates a new empty transaction.
    pub fn empty() -> Self {
        Self {
            version: Version(0),
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![],
        }
    }
}

/// The transaction version.
#[derive(
    Copy,
    PartialEq,
    Eq,
    Clone,
    Debug,
    PartialOrd,
    Ord,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct Version(pub i32);

/// An absolute lock time value, representing either a block height or a UNIX timestamp (seconds
/// since epoch).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub enum LockTime {
    /// A block height lock time value.
    Blocks(Height),
    /// A UNIX timestamp lock time value.
    Seconds(Time),
}

/// An absolute block height, guaranteed to always contain a valid height value.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct Height(u32);

/// A UNIX timestamp, seconds since epoch, guaranteed to always contain a valid time value.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct Time(u32);

impl Time {
    /// The minimum absolute block time (Tue Nov 05 1985 00:53:20 GMT+0000).
    pub const MIN: Self = Time(bitcoin::absolute::LOCK_TIME_THRESHOLD);
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct TxIn {
    /// The reference to the previous output that is being used as an input.
    pub previous_output: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to be accepted.
    pub script_sig: ScriptBuf,
    /// The sequence number
    pub sequence: Sequence,
    /// Witness data: an array of byte-arrays.
    pub witness: Witness,
}

/// A reference to a transaction output.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    PartialOrd,
    Ord,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct OutPoint {
    /// The referenced transaction's txid.
    pub txid: Txid,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}

/// A bitcoin transaction hash/transaction ID.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    PartialOrd,
    Ord,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct Txid([u8; 32]);

/// An owned, growable script.
#[derive(
    Clone,
    Debug,
    Default,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct ScriptBuf(Vec<u8>);

/// Bitcoin transaction input sequence number.
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct Sequence(pub u32);

/// The Witness is the data used to unlock bitcoin since the [segwit upgrade].
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct Witness {
    /// Contains the witness `Vec<Vec<u8>>` serialization
    content: Vec<u8>,

    /// The number of elements in the witness.
    witness_elements: usize,

    /// This is the valid index pointing to the beginning of the index area.
    indices_start: usize,
}

/// Bitcoin transaction output.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct TxOut {
    /// The value of the output, in satoshis.
    pub value: Amount,
    /// The script which must be satisfied for the output to be spent.
    pub script_pubkey: ScriptBuf,
}

/// Amount
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct Amount(u64);

// FIXME: try to use https://docs.rs/frunk/latest/frunk/#transmogrifying

impl From<BitTransaction> for OurTransaction {
    fn from(value: BitTransaction) -> Self {
        // this is possible because their fields are equal
        let json = serde_json::to_string(&value).unwrap();
        let res = serde_json::from_str(&json).unwrap();
        res
    }
}

impl From<&BitTransaction> for OurTransaction {
    fn from(value: &BitTransaction) -> Self {
        // this is possible because their fields are equal
        let json = serde_json::to_string(value).unwrap();
        let res = serde_json::from_str(&json).unwrap();
        res
    }
}

impl From<OurTransaction> for BitTransaction {
    fn from(value: OurTransaction) -> Self {
        // this is possible because their fields are equal
        let json = serde_json::to_string(&value).unwrap();
        let res = serde_json::from_str(&json).unwrap();
        res
    }
}

impl From<&OurTransaction> for BitTransaction {
    fn from(value: &OurTransaction) -> Self {
        // this is possible because their fields are equal
        let json = serde_json::to_string(value).unwrap();
        let res = serde_json::from_str(&json).unwrap();
        res
    }
}
