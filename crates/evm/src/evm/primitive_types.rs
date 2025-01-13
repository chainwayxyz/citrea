use std::ops::{Deref, Range};

use alloy_primitives::{Address, BlockNumber, Bloom, Bytes, Sealable, B256, B64, U256};
use alloy_rlp::bytes::BufMut;
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
#[cfg(feature = "native")]
use reth_primitives::TransactionSignedEcRecovered;
use reth_primitives::{Header as AlloyHeader, SealedHeader, TransactionSigned};
use serde::{Deserialize, Serialize};

#[cfg(feature = "native")]
use crate::evm::compat::DoNotUseTransactionSigned;

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

/// This is the old version of the Header we launched testnet with with Reth v1.0.4
/// This is used because the new alloy_consensus::Header has new serde attributes and some type changes, which causes different state roots
/// In the future, before mainnet, we will be using alloy_consensus::Header encode() and decode() functions to have backwards compatible encoding and decoding
/// Ethereum Block header
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct DoNotUseHeader {
    /// The Keccak 256-bit hash of the parent
    /// block’s header, in its entirety; formally Hp.
    pub parent_hash: B256,
    /// The Keccak 256-bit hash of the ommers list portion of this block; formally Ho.
    pub ommers_hash: B256,
    /// The 160-bit address to which all fees collected from the successful mining of this block
    /// be transferred; formally Hc.
    pub beneficiary: Address,
    /// The Keccak 256-bit hash of the root node of the state trie, after all transactions are
    /// executed and finalisations applied; formally Hr.
    pub state_root: B256,
    /// The Keccak 256-bit hash of the root node of the trie structure populated with each
    /// transaction in the transactions list portion of the block; formally Ht.
    pub transactions_root: B256,
    /// The Keccak 256-bit hash of the root node of the trie structure populated with the receipts
    /// of each transaction in the transactions list portion of the block; formally He.
    pub receipts_root: B256,
    /// The Keccak 256-bit hash of the withdrawals list portion of this block.
    ///
    /// See [EIP-4895](https://eips.ethereum.org/EIPS/eip-4895).
    pub withdrawals_root: Option<B256>,
    /// The Bloom filter composed from indexable information (logger address and log topics)
    /// contained in each log entry from the receipt of each transaction in the transactions list;
    /// formally Hb.
    pub logs_bloom: Bloom,
    /// A scalar value corresponding to the difficulty level of this block. This can be calculated
    /// from the previous block’s difficulty level and the timestamp; formally Hd.
    pub difficulty: U256,
    /// A scalar value equal to the number of ancestor blocks. The genesis block has a number of
    /// zero; formally Hi.
    pub number: BlockNumber,
    /// A scalar value equal to the current limit of gas expenditure per block; formally Hl.
    pub gas_limit: u64,
    /// A scalar value equal to the total gas used in transactions in this block; formally Hg.
    pub gas_used: u64,
    /// A scalar value equal to the reasonable output of Unix’s time() at this block’s inception;
    /// formally Hs.
    pub timestamp: u64,
    /// A 256-bit hash which, combined with the
    /// nonce, proves that a sufficient amount of computation has been carried out on this block;
    /// formally Hm.
    pub mix_hash: B256,
    /// A 64-bit value which, combined with the mixhash, proves that a sufficient amount of
    /// computation has been carried out on this block; formally Hn.
    pub nonce: u64,
    /// A scalar representing EIP1559 base fee which can move up or down each block according
    /// to a formula which is a function of gas used in parent block and gas target
    /// (block gas limit divided by elasticity multiplier) of parent block.
    /// The algorithm results in the base fee per gas increasing when blocks are
    /// above the gas target, and decreasing when blocks are below the gas target. The base fee per
    /// gas is burned.
    pub base_fee_per_gas: Option<u64>,
    /// The total amount of blob gas consumed by the transactions within the block, added in
    /// EIP-4844.
    pub blob_gas_used: Option<u64>,
    /// A running total of blob gas consumed in excess of the target, prior to the block. Blocks
    /// with above-target blob gas consumption increase this value, blocks with below-target blob
    /// gas consumption decrease it (bounded at 0). This was added in EIP-4844.
    pub excess_blob_gas: Option<u64>,
    /// The hash of the parent beacon block's root is included in execution blocks, as proposed by
    /// EIP-4788.
    ///
    /// This enables trust-minimized access to consensus state, supporting staking pools, bridges,
    /// and more.
    ///
    /// The beacon roots contract handles root storage, enhancing Ethereum's functionalities.
    pub parent_beacon_block_root: Option<B256>,
    /// The Keccak 256-bit hash of the root node of the trie structure populated with each
    /// [EIP-7685] request in the block body.
    ///
    /// [EIP-7685]: https://eips.ethereum.org/EIPS/eip-7685
    pub requests_root: Option<B256>,
    /// An arbitrary byte array containing data relevant to this block. This must be 32 bytes or
    /// fewer; formally Hx.
    pub extra_data: Bytes,
}

impl From<DoNotUseHeader> for AlloyHeader {
    fn from(value: DoNotUseHeader) -> Self {
        Self {
            parent_hash: value.parent_hash,
            ommers_hash: value.ommers_hash,
            beneficiary: value.beneficiary,
            state_root: value.state_root,
            transactions_root: value.transactions_root,
            receipts_root: value.receipts_root,
            withdrawals_root: value.withdrawals_root,
            logs_bloom: value.logs_bloom,
            difficulty: value.difficulty,
            number: value.number,
            gas_limit: value.gas_limit,
            gas_used: value.gas_used,
            timestamp: value.timestamp,
            mix_hash: value.mix_hash,
            nonce: B64::new(value.nonce.to_be_bytes()),
            base_fee_per_gas: value.base_fee_per_gas,
            blob_gas_used: value.blob_gas_used,
            excess_blob_gas: value.excess_blob_gas,
            parent_beacon_block_root: value.parent_beacon_block_root,
            requests_root: value.requests_root,
            extra_data: value.extra_data,
        }
    }
}

impl From<AlloyHeader> for DoNotUseHeader {
    fn from(value: AlloyHeader) -> Self {
        Self {
            parent_hash: value.parent_hash,
            ommers_hash: value.ommers_hash,
            beneficiary: value.beneficiary,
            state_root: value.state_root,
            transactions_root: value.transactions_root,
            receipts_root: value.receipts_root,
            withdrawals_root: value.withdrawals_root,
            logs_bloom: value.logs_bloom,
            difficulty: value.difficulty,
            number: value.number,
            gas_limit: value.gas_limit,
            gas_used: value.gas_used,
            timestamp: value.timestamp,
            mix_hash: value.mix_hash,
            nonce: value.nonce.into(),
            base_fee_per_gas: value.base_fee_per_gas,
            blob_gas_used: value.blob_gas_used,
            excess_blob_gas: value.excess_blob_gas,
            parent_beacon_block_root: value.parent_beacon_block_root,
            requests_root: value.requests_root,
            extra_data: value.extra_data.clone(),
        }
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
pub(crate) struct TransactionSignedAndRecovered {
    /// Signer of the transaction
    pub(crate) signer: Address,
    /// Signed transaction
    pub(crate) signed_transaction: TransactionSigned,
    /// Block the transaction was added to
    pub(crate) block_number: u64,
}

#[cfg(feature = "native")]
/// This uses the old version of the TransactionSigned launched testnet with with Reth v1.0.4
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct DoNotUseTransactionSignedAndRecovered {
    /// Signer of the transaction
    pub(crate) signer: Address,
    /// Signed transaction
    pub(crate) signed_transaction: DoNotUseTransactionSigned,
    /// Block the transaction was added to
    pub(crate) block_number: u64,
}

#[cfg(feature = "native")]
impl From<DoNotUseTransactionSignedAndRecovered> for TransactionSignedAndRecovered {
    fn from(value: DoNotUseTransactionSignedAndRecovered) -> Self {
        Self {
            signer: value.signer,
            signed_transaction: value.signed_transaction.into(),
            block_number: value.block_number,
        }
    }
}

#[cfg(feature = "native")]
impl From<DoNotUseTransactionSignedAndRecovered> for TransactionSignedEcRecovered {
    fn from(value: DoNotUseTransactionSignedAndRecovered) -> Self {
        TransactionSigned {
            hash: value.signed_transaction.hash,
            signature: value.signed_transaction.signature.into(),
            transaction: value.signed_transaction.transaction.into(),
        }
        .into_ecrecovered()
        .unwrap()
    }
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct Block<H> {
    /// Block header.
    pub(crate) header: H,

    /// L1 fee rate.
    pub(crate) l1_fee_rate: u128,

    /// The hash of L1 block that the L2 block corresponds to.  
    pub(crate) l1_hash: B256,

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
            l1_hash: self.l1_hash,
            transactions: self.transactions,
        }
    }
}

impl Block<DoNotUseHeader> {
    pub(crate) fn seal(self) -> SealedBlock {
        let alloy_header = AlloyHeader::from(self.header);
        let sealed = alloy_header.seal_slow();
        let (header, seal) = sealed.into_parts();
        SealedBlock {
            header: SealedHeader::new(header, seal),
            l1_fee_rate: self.l1_fee_rate,
            l1_hash: self.l1_hash,
            transactions: self.transactions,
        }
    }
}

impl From<Block<DoNotUseHeader>> for Block<AlloyHeader> {
    fn from(value: Block<DoNotUseHeader>) -> Self {
        Self {
            header: value.header.into(),
            l1_fee_rate: value.l1_fee_rate,
            l1_hash: value.l1_hash,
            transactions: value.transactions,
        }
    }
}

impl From<Block<AlloyHeader>> for Block<DoNotUseHeader> {
    fn from(value: Block<AlloyHeader>) -> Self {
        Self {
            header: value.header.into(),
            l1_fee_rate: value.l1_fee_rate,
            l1_hash: value.l1_hash,
            transactions: value.transactions,
        }
    }
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DoNotUseSealedBlock {
    /// Block header.
    pub(crate) header: SealedHeader<DoNotUseHeader>,

    /// L1 fee rate.
    pub(crate) l1_fee_rate: u128,

    /// The hash of L1 block that the L2 block corresponds to.  
    pub(crate) l1_hash: B256,

    /// Transactions in this block.
    pub(crate) transactions: Range<u64>,
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SealedBlock {
    /// Block header.
    pub(crate) header: SealedHeader<AlloyHeader>,

    /// L1 fee rate.
    pub(crate) l1_fee_rate: u128,

    /// The hash of L1 block that the L2 block corresponds to.  
    pub(crate) l1_hash: B256,

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
        rlp_head.payload_length += self.l1_hash.length();
        rlp_head.payload_length += self.transactions.start.length();
        rlp_head.payload_length += self.transactions.end.length();
        rlp_head.encode(out);
        let header: AlloyHeader = self.header.clone();
        header.encode(out);
        self.l1_fee_rate.encode(out);
        self.l1_hash.encode(out);
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
        let l1_hash = Decodable::decode(b)?;
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
            l1_hash,
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
        rlp_head.payload_length += self.l1_hash.length();
        rlp_head.payload_length += self.transactions.start.length();
        rlp_head.payload_length += self.transactions.end.length();
        rlp_head.encode(out);
        let header: SealedHeader = self.header.clone();
        header.encode(out);
        self.l1_fee_rate.encode(out);
        self.l1_hash.encode(out);
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
        let l1_hash = Decodable::decode(b)?;
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
            l1_hash,
            transactions: Range { start, end },
        })
    }
}

impl From<DoNotUseSealedBlock> for SealedBlock {
    fn from(value: DoNotUseSealedBlock) -> Self {
        let alloy_header = AlloyHeader::from(value.header.deref().clone());
        let sealed = alloy_header.seal_slow();
        let (header, seal) = sealed.into_parts();
        Self {
            header: SealedHeader::new(header, seal),
            l1_fee_rate: value.l1_fee_rate,
            l1_hash: value.l1_hash,
            transactions: value.transactions,
        }
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
pub(crate) struct Receipt {
    pub(crate) receipt: reth_primitives::Receipt,
    pub(crate) gas_used: u128,
    pub(crate) log_index_start: u64,
    pub(crate) l1_diff_size: u64,
}
