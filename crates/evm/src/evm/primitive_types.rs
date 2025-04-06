use std::ops::Range;

use alloy_primitives::{Address, Sealable};
use alloy_rlp::bytes::BufMut;
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use reth_primitives::{Header as AlloyHeader, SealedHeader, TransactionSigned};

/// Rlp encoded evm transaction.
#[derive(
    borsh::BorshDeserialize,
    borsh::BorshSerialize,
    Debug,
    PartialEq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct RlpEvmTransaction {
    /// Rlp data.
    pub rlp: Vec<u8>,
}

#[derive(
    Debug,
    PartialEq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    RlpEncodable,
    RlpDecodable,
    Default,
    Eq,
)]
pub(crate) struct TransactionSignedAndRecovered {
    /// Signer of the transaction
    pub(crate) signer: Address,
    /// Signed transaction
    pub(crate) signed_transaction: TransactionSigned,
    /// Block the transaction was added to
    pub(crate) block_number: u64,
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct Block<H> {
    /// Block header.
    pub(crate) header: H,

    /// L1 fee rate.
    pub(crate) l1_fee_rate: u128,

    /// Transactions in this block.
    pub(crate) transactions: Range<u64>,
}

impl Block<AlloyHeader> {
    pub(crate) fn seal(self) -> SealedBlock {
        let alloy_header = self.header;
        let sealed = alloy_header.seal_slow();
        let (header, seal) = sealed.into_parts();
        SealedBlock {
            header: SealedHeader::new(header, seal),
            l1_fee_rate: self.l1_fee_rate,
            transactions: self.transactions,
        }
    }
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SealedBlock {
    /// Block header.
    pub(crate) header: SealedHeader<AlloyHeader>,

    /// L1 fee rate.
    pub(crate) l1_fee_rate: u128,

    /// Transactions in this block.
    pub(crate) transactions: Range<u64>,
}

impl Encodable for Block<AlloyHeader> {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut rlp_head = alloy_rlp::Header {
            list: true,
            payload_length: 0,
        };
        rlp_head.payload_length += self.header.length();
        rlp_head.payload_length += self.l1_fee_rate.length();
        rlp_head.payload_length += self.transactions.start.length();
        rlp_head.payload_length += self.transactions.end.length();
        rlp_head.encode(out);
        self.header.encode(out);
        self.l1_fee_rate.encode(out);
        self.transactions.start.encode(out);
        self.transactions.end.encode(out);
    }
}

impl Decodable for Block<AlloyHeader> {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let b = &mut &**buf;
        let rlp_head = alloy_rlp::Header::decode(b)?;
        if !rlp_head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let started_len = b.len();

        let header = AlloyHeader::decode(b)?;
        let l1_fee_rate = Decodable::decode(b)?;
        let start = Decodable::decode(b)?;
        let end = Decodable::decode(b)?;

        let consumed = started_len - b.len();
        if consumed != rlp_head.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: rlp_head.payload_length,
                got: consumed,
            });
        }
        *buf = *b;

        Ok(Self {
            header,
            l1_fee_rate,
            transactions: Range { start, end },
        })
    }
}

impl Encodable for SealedBlock {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut rlp_head = alloy_rlp::Header {
            list: true,
            payload_length: 0,
        };
        rlp_head.payload_length += self.header.length();
        rlp_head.payload_length += self.l1_fee_rate.length();
        rlp_head.payload_length += self.transactions.start.length();
        rlp_head.payload_length += self.transactions.end.length();
        rlp_head.encode(out);
        self.header.encode(out);
        self.l1_fee_rate.encode(out);
        self.transactions.start.encode(out);
        self.transactions.end.encode(out);
    }
}

impl Decodable for SealedBlock {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let b = &mut &**buf;
        let rlp_head = alloy_rlp::Header::decode(b)?;
        if !rlp_head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let started_len = b.len();

        let header = SealedHeader::decode(b)?;
        let l1_fee_rate = Decodable::decode(b)?;
        let start = Decodable::decode(b)?;
        let end = Decodable::decode(b)?;

        let consumed = started_len - b.len();
        if consumed != rlp_head.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: rlp_head.payload_length,
                got: consumed,
            });
        }
        *buf = *b;

        Ok(Self {
            header,
            l1_fee_rate,
            transactions: Range { start, end },
        })
    }
}

#[derive(
    Debug,
    PartialEq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    RlpEncodable,
    RlpDecodable,
    Default,
    Eq,
)]
pub(crate) struct CitreaReceiptWithBloom {
    pub(crate) receipt: reth_primitives::ReceiptWithBloom<reth_primitives::Receipt>,
    pub(crate) gas_used: u64,
    pub(crate) log_index_start: u64,
    pub(crate) l1_diff_size: u64,
}
