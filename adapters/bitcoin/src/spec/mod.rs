use bitcoin::Transaction;
use sov_rollup_interface::da::DaSpec;

use self::address::AddressWrapper;
use self::blob::BlobWithSender;
use self::block_hash::BlockHashWrapper;
use self::header::HeaderWrapper;
use self::proof::InclusionMultiProof;

use crate::verifier::ChainValidityCondition;

pub mod address;
pub mod blob;
pub mod block;
mod block_hash;
pub mod header;
pub mod proof;
pub mod transaction;
pub mod utxo;

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
pub struct BitcoinSpec;

pub struct RollupParams {
    pub rollup_name: String,
}

impl DaSpec for BitcoinSpec {
    type SlotHash = BlockHashWrapper;

    type ChainParams = RollupParams;

    type BlockHeader = HeaderWrapper;

    type BlobTransaction = BlobWithSender;

    type Address = AddressWrapper;

    type InclusionMultiProof = InclusionMultiProof;

    type CompletenessProof = Vec<Transaction>;

    type ValidityCondition = ChainValidityCondition;
}
