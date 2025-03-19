use borsh::{BorshDeserialize, BorshSerialize};
use citrea_primitives::compression::decompress_blob;
use serde::{Deserialize, Serialize};
use short_proof::BitcoinHeaderShortProof;
use sov_rollup_interface::da::{DaSpec, DecompressError};

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

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct BitcoinSpec;

pub struct RollupParams {
    pub reveal_tx_prefix: Vec<u8>,
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
        let blob = decompress_blob(complete_chunks).map_err(|_| DecompressError)?;
        borsh::from_slice(blob.as_slice()).map_err(|_| DecompressError)
    }
}
