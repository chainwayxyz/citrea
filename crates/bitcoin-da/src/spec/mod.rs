//! This module defines the Bitcoin DaSpec and its associated types.

use borsh::{BorshDeserialize, BorshSerialize};
use citrea_primitives::compression::decompress_blob;
use serde::{Deserialize, Serialize};
use short_proof::BitcoinHeaderShortProof;
use sov_rollup_interface::da::{DaSpec, DecompressError};
use sov_rollup_interface::Network;

use self::address::AddressWrapper;
use self::blob::BlobWithSender;
use self::block_hash::BlockHashWrapper;
use self::header::HeaderWrapper;
use self::proof::InclusionMultiProof;
use self::transaction::TransactionWrapper;

pub mod address;
pub mod blob;
pub mod block;
mod block_hash;
pub mod header;
#[cfg(feature = "native")]
pub mod header_stream;
pub mod proof;
pub mod short_proof;
pub mod transaction;
pub mod utxo;

/// BitcoinSpec is the specification for the Bitcoin DaSpec.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct BitcoinSpec;

/// RollupParams contains the parameters for the Bitcoin rollup.
pub struct RollupParams {
    /// The prefix used for wtxid prefix.
    pub reveal_tx_prefix: Vec<u8>,
    /// The network this rollup is operating on (e.g., Mainnet, Testnet).
    pub network: Network,
}

impl DaSpec for BitcoinSpec {
    type SlotHash = BlockHashWrapper;

    type ChainParams = RollupParams;

    type BlockHeader = HeaderWrapper;

    type BlobTransaction = BlobWithSender;

    type Address = AddressWrapper;

    type InclusionMultiProof = InclusionMultiProof;

    type CompletenessProof = Vec<TransactionWrapper>;

    type ShortHeaderProof = BitcoinHeaderShortProof;

    fn decompress_chunks(complete_chunks: &[u8]) -> Result<Vec<u8>, DecompressError> {
        decompress_blob(complete_chunks).map_err(|_| DecompressError)
    }
}
