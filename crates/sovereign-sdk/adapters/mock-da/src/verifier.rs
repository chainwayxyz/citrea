use anyhow::anyhow;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{BlobReaderTrait, DaNamespace, DaSpec, DaVerifier, LatestDaState};
use sov_rollup_interface::Network;

use crate::{MockAddress, MockBlob, MockBlockHeader, MockDaVerifier, MockHash};

impl BlobReaderTrait for MockBlob {
    type Address = MockAddress;

    fn sender(&self) -> Self::Address {
        self.address.clone()
    }

    fn hash(&self) -> [u8; 32] {
        self.hash
    }

    fn wtxid(&self) -> Option<[u8; 32]> {
        self.wtxid
    }

    fn full_data(&self) -> &[u8] {
        self.data.accumulator()
    }

    fn total_len(&self) -> usize {
        self.data.total_len()
    }

    fn serialize_v1(&self) -> borsh::io::Result<Vec<u8>> {
        borsh::to_vec(self)
    }

    fn serialize_v2(&self) -> borsh::io::Result<Vec<u8>> {
        borsh::to_vec(self)
    }
}

/// A [`sov_rollup_interface::da::DaSpec`] suitable for testing.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct MockDaSpec;

impl DaSpec for MockDaSpec {
    type SlotHash = MockHash;
    type BlockHeader = MockBlockHeader;
    type BlobTransaction = MockBlob;
    type Address = MockAddress;
    type InclusionMultiProof = [u8; 32];
    type CompletenessProof = Vec<MockBlob>;
    type ChainParams = ();
}

impl DaVerifier for MockDaVerifier {
    type Spec = MockDaSpec;

    type Error = anyhow::Error;

    fn decompress_chunks(&self, complete_chunks: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(complete_chunks.to_vec())
    }

    fn new(_params: <Self::Spec as DaSpec>::ChainParams) -> Self {
        Self {}
    }

    fn verify_transactions(
        &self,
        _block_header: &<Self::Spec as DaSpec>::BlockHeader,
        _inclusion_proof: <Self::Spec as DaSpec>::InclusionMultiProof,
        completeness_proof: <Self::Spec as DaSpec>::CompletenessProof,
        _namespace: DaNamespace,
    ) -> Result<Vec<<Self::Spec as DaSpec>::BlobTransaction>, Self::Error> {
        Ok(completeness_proof)
    }

    fn verify_header_chain(
        &self,
        latest_da_state: Option<&LatestDaState>,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
        _network: Network,
    ) -> Result<LatestDaState, Self::Error> {
        let Some(latest_da_state) = latest_da_state else {
            return Ok(LatestDaState {
                block_hash: block_header.hash.0,
                block_height: block_header.height,
                total_work: [0; 32],
                current_target_bits: 0,
                epoch_start_time: 0,
                prev_11_timestamps: [0; 11],
            });
        };
        // Check block heights are consecutive
        if block_header.height - 1 != latest_da_state.block_height {
            return Err(anyhow!("Block heights are not consecutive"));
        }
        // Check prev hash matches with prev light client proof hash
        if block_header.prev_hash.0 != latest_da_state.block_hash {
            return Err(anyhow!(
                "Block prev hash does not match with prev light client proof hash"
            ));
        }
        // Skip hash, bits, pow and timestamp checks for now

        Ok(LatestDaState {
            block_hash: block_header.hash.0,
            block_height: block_header.height,
            total_work: [0; 32],
            current_target_bits: 0,
            epoch_start_time: 0,
            prev_11_timestamps: [0; 11],
        })
    }
}
