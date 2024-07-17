use core::ops::{Deref, DerefMut};

use bitcoin::absolute::{LockTime, Time};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::Transaction as BitcoinTransaction;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// TransactionWrapper is a wrapper around BlockHash to implement borsh serde
#[derive(Clone, PartialEq, Eq, Debug, Hash, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct TransactionWrapper {
    tx: BitcoinTransaction,
}

impl TransactionWrapper {
    pub fn empty() -> Self {
        let tx = BitcoinTransaction {
            version: bitcoin::transaction::Version(0),
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![],
        };
        Self { tx }
    }

    pub fn inner(&self) -> &BitcoinTransaction {
        &self.tx
    }
}

impl BorshSerialize for TransactionWrapper {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        Encodable::consensus_encode(&self.tx, writer)
            .expect("Bitcoin Transaction serialization cannot fail");
        Ok(())
    }
}

impl BorshDeserialize for TransactionWrapper {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let tx = Decodable::consensus_decode(reader)
            .expect("Bitcoin Transaction deserialization cannot fail");
        Ok(Self { tx })
    }
}

impl Deref for TransactionWrapper {
    type Target = BitcoinTransaction;
    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl DerefMut for TransactionWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

impl From<BitcoinTransaction> for TransactionWrapper {
    fn from(tx: BitcoinTransaction) -> Self {
        Self { tx }
    }
}
