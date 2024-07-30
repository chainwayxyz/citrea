use core::ops::{Deref, DerefMut};

use bitcoin::absolute::{LockTime, Time};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// TransactionWrapper is a wrapper around BlockHash to implement borsh serde
#[derive(Clone, PartialEq, Eq, Debug, Hash, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct TransactionWrapper {
    tx: Transaction,
}

impl TransactionWrapper {
    pub fn empty() -> Self {
        let tx = Transaction {
            version: bitcoin::transaction::Version(0),
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![],
        };
        Self { tx }
    }

    pub fn inner(&self) -> &Transaction {
        &self.tx
    }
}

impl BorshSerialize for TransactionWrapper {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.tx.version.0, writer)?;
        BorshSerialize::serialize(&self.tx.lock_time.to_consensus_u32(), writer)?;
        BorshSerialize::serialize(&self.tx.input.len(), writer)?;
        for input in &self.tx.input {
            serialize_txin(input, writer)?;
        }
        BorshSerialize::serialize(&self.tx.output.len(), writer)?;
        for output in &self.tx.output {
            serialize_txout(output, writer)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for TransactionWrapper {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let version = Version(i32::deserialize_reader(reader)?);
        let lock_time = LockTime::from_consensus(u32::deserialize_reader(reader)?);
        let input_len = usize::deserialize_reader(reader)?;
        let mut input = Vec::with_capacity(input_len);
        for _ in 0..input_len {
            input.push(deserialize_txin(reader)?);
        }
        let output_len = usize::deserialize_reader(reader)?;
        let mut output = Vec::with_capacity(output_len);
        for _ in 0..output_len {
            output.push(deserialize_txout(reader)?);
        }

        let tx = Transaction {
            version,
            lock_time,
            input,
            output,
        };

        Ok(Self { tx })
    }
}

fn serialize_txin<W: borsh::io::Write>(txin: &TxIn, writer: &mut W) -> borsh::io::Result<()> {
    BorshSerialize::serialize(&txin.previous_output.txid.to_byte_array(), writer)?;
    BorshSerialize::serialize(&txin.previous_output.vout, writer)?;
    BorshSerialize::serialize(&txin.script_sig.as_bytes(), writer)?;
    BorshSerialize::serialize(&txin.sequence.0, writer)?;
    BorshSerialize::serialize(&txin.witness.to_vec(), writer)
}

fn deserialize_txin<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<TxIn> {
    let txid = bitcoin::Txid::from_byte_array(<[u8; 32]>::deserialize_reader(reader)?);
    let vout = u32::deserialize_reader(reader)?;
    let script_sig = ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?);
    let sequence = Sequence(u32::deserialize_reader(reader)?);
    let witness = Witness::from(Vec::<Vec<u8>>::deserialize_reader(reader)?);

    Ok(TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig,
        sequence,
        witness,
    })
}

fn serialize_txout<W: borsh::io::Write>(txout: &TxOut, writer: &mut W) -> borsh::io::Result<()> {
    BorshSerialize::serialize(&txout.value.to_sat(), writer)?;
    BorshSerialize::serialize(&txout.script_pubkey.as_bytes(), writer)
}

fn deserialize_txout<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<TxOut> {
    let value = Amount::from_sat(u64::deserialize_reader(reader)?);
    let script_pubkey = ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?);

    Ok(TxOut {
        value,
        script_pubkey,
    })
}

impl Deref for TransactionWrapper {
    type Target = Transaction;
    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl DerefMut for TransactionWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

impl From<Transaction> for TransactionWrapper {
    fn from(tx: Transaction) -> Self {
        Self { tx }
    }
}
