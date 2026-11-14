//! This module provides a wrapper around Bitcoin transactions to implement
//! borsh serialization and deserialization.

use core::ops::{Deref, DerefMut};

use bitcoin::consensus::encode::VarInt;
use bitcoin::consensus::Decodable;
use bitcoin::{Transaction, Witness};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::helpers::calculate_double_sha256;
use crate::helpers::parsers::REVEAL_WITNESS_LEN;

/// TransactionWrapper is a wrapper around BlockHash to implement borsh serde
#[derive(Clone, PartialEq, Eq, Debug, Hash, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct TransactionWrapper(Transaction);

impl BorshSerialize for TransactionWrapper {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&RawTransaction::from(self), writer)
    }
}

impl BorshDeserialize for TransactionWrapper {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        RawTransaction::deserialize_reader(reader)?
            .decode()
            .map(Self)
            .map_err(|_| {
                borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    "invalid transaction consensus encoding",
                )
            })
    }
}

impl Deref for TransactionWrapper {
    type Target = Transaction;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TransactionWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Transaction> for TransactionWrapper {
    fn from(tx: Transaction) -> Self {
        Self(tx)
    }
}

/// A completeness proof transaction in its consensus encoding.
///
/// The circuit only needs the wtxid of a prefix-matching transaction and the witness of its
/// first input. Keeping the encoding lets it skip every other witness: decoding a full
/// `Transaction` costs guest cycles for each witness element, which a transaction padded with
/// empty elements turns into a proving denial of service.
#[derive(
    Clone, PartialEq, Eq, Debug, Hash, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct RawTransaction(#[serde(with = "hex::serde")] Vec<u8>);

impl RawTransaction {
    /// The consensus encoding of the transaction.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Computes the wtxid by hashing the encoding.
    pub fn wtxid(&self) -> [u8; 32] {
        calculate_double_sha256(&self.0)
    }

    /// Decodes the whole transaction.
    pub fn decode(&self) -> Result<Transaction, bitcoin::consensus::encode::Error> {
        bitcoin::consensus::deserialize(&self.0)
    }

    /// Returns the first input's witness if it has `REVEAL_WITNESS_LEN` elements.
    ///
    /// Only the inputs and outputs before the witnesses are walked, and no other input's
    /// witness is read, so the cost does not depend on how many witness elements the
    /// transaction carries.
    pub fn reveal_witness(&self) -> Option<Witness> {
        let mut reader = self.0.as_slice();
        take(&mut reader, 4)?; // version
        if read_compact_size(&mut reader)? != 0 {
            // Without the segwit marker there are no witnesses.
            return None;
        }
        if take(&mut reader, 1)? != [1] {
            return None;
        }
        let input_count = read_compact_size(&mut reader)?;
        if input_count == 0 {
            return None;
        }
        for _ in 0..input_count {
            take(&mut reader, 36)?; // previous output
            let script_sig_len = read_compact_size(&mut reader)?;
            take(&mut reader, usize::try_from(script_sig_len).ok()?)?;
            take(&mut reader, 4)?; // sequence
        }
        let output_count = read_compact_size(&mut reader)?;
        for _ in 0..output_count {
            take(&mut reader, 8)?; // value
            let script_pubkey_len = read_compact_size(&mut reader)?;
            take(&mut reader, usize::try_from(script_pubkey_len).ok()?)?;
        }

        let mut peek = reader;
        if read_compact_size(&mut peek)? != REVEAL_WITNESS_LEN as u64 {
            return None;
        }
        Witness::consensus_decode(&mut reader).ok()
    }
}

impl From<&Transaction> for RawTransaction {
    fn from(tx: &Transaction) -> Self {
        Self(bitcoin::consensus::serialize(tx))
    }
}

impl From<Transaction> for RawTransaction {
    fn from(tx: Transaction) -> Self {
        Self::from(&tx)
    }
}

impl From<&TransactionWrapper> for RawTransaction {
    fn from(tx: &TransactionWrapper) -> Self {
        Self::from(&tx.0)
    }
}

fn take<'a>(reader: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if reader.len() < len {
        return None;
    }
    let (head, tail) = reader.split_at(len);
    *reader = tail;
    Some(head)
}

fn read_compact_size(reader: &mut &[u8]) -> Option<u64> {
    VarInt::consensus_decode(reader).ok().map(|n| n.0)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use borsh::io::Read;
    use borsh::BorshDeserialize;

    use super::{RawTransaction, TransactionWrapper};

    /// Counts guest-side Borsh reads.
    struct CountingReader<'a> {
        inner: &'a [u8],
        reads: usize,
    }

    impl Read for CountingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> borsh::io::Result<usize> {
            self.reads += 1;
            let n = core::cmp::min(buf.len(), self.inner.len());
            buf[..n].copy_from_slice(&self.inner[..n]);
            self.inner = &self.inner[n..];
            Ok(n)
        }
    }

    fn flood_tx(inputs: usize, empties_per_input: usize) -> TransactionWrapper {
        let mut witness = Witness::new();
        for _ in 0..empties_per_input {
            witness.push([]);
        }
        witness.push([0x51]);
        witness.push([0u8; 33]);

        TransactionWrapper::from(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: (0..inputs)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([i as u8; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: witness.clone(),
                })
                .collect(),
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        })
    }

    fn output_flood_coinbase(outputs: usize) -> TransactionWrapper {
        TransactionWrapper::from(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: bitcoin::Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
                };
                outputs
            ],
        })
    }

    #[test]
    fn witness_blob_roundtrips_a_consensus_decoded_segwit_tx() {
        // This is the consensus-decoded witness layout stored by the native LCP.
        let hex = "020000000001013a66019bfcc719ba12586a83ebbb0b3debdc945f563cd64fd44c8044e3d3a1790100000000fdffffff028fa2aa060000000017a9147ba15d4e0d8334de3a68cf3687594e2d1ee5b00d879179e0090000000016001493c93ad222e57d65438545e048822ede2d418a3d0247304402202432e6c422b93705fbc57b350ea43e4ef9441c0907988eff051eaac807fc8cf2022046c92b540b5f04f8da11febb5d2a478aed1b8bc088e769da8b78fffcae8c9a9a012103e2991b47d9c788f55379f9ef519b642d79d7dfe0e7555ec5575ee934b2dca1223f5d0c00";
        let raw = hex::decode(hex).unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        let wrapped = TransactionWrapper::from(tx);
        let decoded =
            TransactionWrapper::try_from_slice(&borsh::to_vec(&wrapped).unwrap()).unwrap();
        assert_eq!(*wrapped, *decoded);
        assert_eq!(wrapped.compute_wtxid(), decoded.compute_wtxid());
    }

    #[test]
    fn transaction_wrapper_roundtrips_an_empty_witness() {
        let tx = TransactionWrapper::from(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x51]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(546),
                script_pubkey: ScriptBuf::new(),
            }],
        });

        let decoded = TransactionWrapper::try_from_slice(&borsh::to_vec(&tx).unwrap()).unwrap();
        assert_eq!(*tx, *decoded);
        assert!(decoded.input[0].witness.is_empty());
    }

    #[test]
    fn transaction_wrapper_roundtrips_a_typical_reveal_witness() {
        let mut witness = Witness::new();
        witness.push([0u8; 64]);
        witness.push([0x20; 80]);
        witness.push([0x33; 33]);
        let tx = TransactionWrapper::from(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(546),
                script_pubkey: ScriptBuf::new(),
            }],
        });

        let bytes = borsh::to_vec(&tx).unwrap();
        let decoded = TransactionWrapper::try_from_slice(&bytes).unwrap();
        assert_eq!(*tx, *decoded);
    }

    #[test]
    fn witness_flood_borsh_does_not_issue_one_read_per_empty_element() {
        // A scaled-down flood is enough to expose per-element reads.
        const INPUTS: usize = 8;
        const EMPTIES_PER_INPUT: usize = 256;
        let empty_elements = INPUTS * EMPTIES_PER_INPUT;
        let tx = flood_tx(INPUTS, EMPTIES_PER_INPUT);

        let bytes = borsh::to_vec(&tx).unwrap();
        let mut reader = CountingReader {
            inner: &bytes,
            reads: 0,
        };
        let decoded = TransactionWrapper::deserialize_reader(&mut reader).unwrap();
        assert_eq!(*tx, *decoded);

        assert!(
            reader.reads < empty_elements / 4,
            "expected far fewer reads than empty stack elements ({} reads for {empty_elements} empties)",
            reader.reads
        );

        // An empty element costs one VarInt byte, not a four byte length.
        assert!(
            bytes.len() < empty_elements * 2,
            "expected ~1 byte per empty stack element, got {} bytes for {empty_elements} empties",
            bytes.len()
        );
    }

    #[test]
    fn output_flood_borsh_does_not_issue_one_read_per_output() {
        const OUTPUTS: usize = 99_000;
        let tx = output_flood_coinbase(OUTPUTS);

        assert!(tx.weight().to_wu() < 4_000_000);

        let bytes = borsh::to_vec(&tx).unwrap();
        let mut reader = CountingReader {
            inner: &bytes,
            reads: 0,
        };
        let decoded = TransactionWrapper::deserialize_reader(&mut reader).unwrap();
        assert_eq!(*tx, *decoded);
        assert!(
            reader.reads < 16,
            "expected transaction bytes to be read in bulk, got {} reads for {OUTPUTS} outputs",
            reader.reads
        );
    }

    fn reveal_witness() -> Witness {
        let mut witness = Witness::new();
        witness.push([0x01; 64]);
        witness.push([0x51]);
        witness.push([0xc0; 33]);
        witness
    }

    #[test]
    fn raw_transaction_roundtrips_and_hashes_to_the_wtxid() {
        let tx = flood_tx(4, 16);
        let raw = RawTransaction::from(&*tx);

        assert_eq!(raw.wtxid(), tx.compute_wtxid().to_byte_array());
        assert_eq!(raw.decode().unwrap(), *tx);
        let decoded = RawTransaction::try_from_slice(&borsh::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(decoded, raw);
        let json = serde_json::to_string(&raw).unwrap();
        assert_eq!(serde_json::from_str::<RawTransaction>(&json).unwrap(), raw);
    }

    #[test]
    fn raw_transaction_rejects_a_flooded_first_input_witness() {
        let raw = RawTransaction::from(&*flood_tx(8, 256));
        assert_eq!(raw.reveal_witness(), None);
    }

    #[test]
    fn raw_transaction_does_not_read_witnesses_after_the_first_input() {
        let mut tx = flood_tx(8, 256);
        tx.input[0].witness = reveal_witness();
        let raw = RawTransaction::from(&*tx);
        assert_eq!(raw.reveal_witness(), Some(reveal_witness()));

        // Cut the encoding right after the first input's witness.
        let first_witness_len = bitcoin::consensus::serialize(&reveal_witness()).len();
        let mut no_witness_tx = (*tx).clone();
        for input in &mut no_witness_tx.input {
            input.witness = Witness::new();
        }
        let prefix_len = bitcoin::consensus::serialize(&no_witness_tx).len() - 4 + 2;
        let truncated = RawTransaction(raw.as_bytes()[..prefix_len + first_witness_len].to_vec());
        assert_eq!(truncated.reveal_witness(), Some(reveal_witness()));
    }

    fn expected_reveal_witness(raw: &RawTransaction) -> Option<Witness> {
        let tx = raw.decode().ok()?;
        let witness = &tx.input.first()?.witness;
        (witness.len() == super::REVEAL_WITNESS_LEN).then(|| witness.clone())
    }

    #[test]
    fn raw_transaction_reveal_witness_matches_full_decode() {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        // Lengths around the compact size boundaries.
        let lengths = [0usize, 1, 32, 252, 253, 520, 0xffff, 0x10000];
        let random_bytes = |rng: &mut rand::rngs::StdRng| {
            let len = if rng.gen_bool(0.02) {
                lengths[rng.gen_range(0..lengths.len())]
            } else {
                rng.gen_range(0..80)
            };
            (0..len).map(|_| rng.gen()).collect::<Vec<u8>>()
        };

        for _ in 0..300 {
            let input_count = rng.gen_range(1..5);
            let output_count = rng.gen_range(0..4);
            let input = (0..input_count)
                .map(|_| {
                    let mut witness = Witness::new();
                    let elements = match rng.gen_range(0..4) {
                        0 => 0,
                        1 => super::REVEAL_WITNESS_LEN,
                        2 => super::REVEAL_WITNESS_LEN + 1,
                        _ => rng.gen_range(0..300),
                    };
                    for _ in 0..elements {
                        witness.push(random_bytes(&mut rng));
                    }
                    TxIn {
                        previous_output: OutPoint {
                            txid: Txid::from_byte_array(rng.gen()),
                            vout: rng.gen(),
                        },
                        script_sig: ScriptBuf::from_bytes(random_bytes(&mut rng)),
                        sequence: Sequence(rng.gen()),
                        witness,
                    }
                })
                .collect();
            let output = (0..output_count)
                .map(|_| TxOut {
                    value: bitcoin::Amount::from_sat(rng.gen()),
                    script_pubkey: ScriptBuf::from_bytes(random_bytes(&mut rng)),
                })
                .collect();
            let tx = Transaction {
                version: bitcoin::transaction::Version(rng.gen()),
                lock_time: bitcoin::absolute::LockTime::from_consensus(rng.gen()),
                input,
                output,
            };

            let raw = RawTransaction::from(&tx);
            assert_eq!(raw.wtxid(), tx.compute_wtxid().to_byte_array());
            assert_eq!(raw.reveal_witness(), expected_reveal_witness(&raw));
        }
    }

    #[test]
    fn raw_transaction_only_reads_the_first_input_witness() {
        let mut tx = flood_tx(3, 0);
        tx.input[0].witness = Witness::new();
        tx.input[1].witness = reveal_witness();
        assert_eq!(RawTransaction::from(&*tx).reveal_witness(), None);

        // An annex makes the witness four elements long.
        let mut with_annex = reveal_witness();
        with_annex.push([0x50, 0x00]);
        tx.input[0].witness = with_annex;
        assert_eq!(RawTransaction::from(&*tx).reveal_witness(), None);
    }

    #[test]
    fn raw_transaction_without_witnesses_has_no_reveal_witness() {
        let mut tx = flood_tx(1, 0);
        tx.input[0].witness = Witness::new();
        let raw = RawTransaction::from(&*tx);
        assert_eq!(raw.wtxid(), tx.compute_wtxid().to_byte_array());
        assert_eq!(raw.reveal_witness(), None);
    }
}
