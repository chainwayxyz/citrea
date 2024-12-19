use anyhow::anyhow;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{
    BlobReaderTrait, BlockHeaderTrait, DaNamespace, DaSpec, DaVerifier, UpdatedDaState,
};

use crate::{MockAddress, MockBlob, MockBlockHeader, MockDaVerifier, MockHash};

impl BlobReaderTrait for MockBlob {
    type Address = MockAddress;

    fn sender(&self) -> Self::Address {
        self.address.clone()
    }

    fn hash(&self) -> [u8; 32] {
        self.hash
    }

    fn verified_data(&self) -> &[u8] {
        self.data.accumulator()
    }

    fn total_len(&self) -> usize {
        self.data.total_len()
    }

    #[cfg(feature = "native")]
    fn advance(&mut self, num_bytes: usize) -> &[u8] {
        self.data.advance(num_bytes);
        self.verified_data()
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
    type CompletenessProof = ();
    type ChainParams = ();
}

impl DaVerifier for MockDaVerifier {
    type Spec = MockDaSpec;

    type Error = anyhow::Error;

    fn new(_params: <Self::Spec as DaSpec>::ChainParams) -> Self {
        Self {}
    }

    fn verify_transactions(
        &self,
        _block_header: &<Self::Spec as DaSpec>::BlockHeader,
        _txs: &[<Self::Spec as DaSpec>::BlobTransaction],
        _inclusion_proof: <Self::Spec as DaSpec>::InclusionMultiProof,
        _completeness_proof: <Self::Spec as DaSpec>::CompletenessProof,
        _namespace: DaNamespace,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_header_chain(
        &self,
        previous_light_client_proof_output: &Option<
            sov_rollup_interface::zk::LightClientCircuitOutput<Self::Spec>,
        >,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
    ) -> Result<UpdatedDaState<Self::Spec>, Self::Error> {
        let Some(previous_light_client_proof_output) = previous_light_client_proof_output else {
            return Ok(UpdatedDaState {
                hash: block_header.hash,
                height: block_header.height,
                total_work: [0; 32],
                epoch_start_time: block_header.time.secs() as u32,
                prev_11_timestamps: [0; 11],
                current_target_bits: block_header.bits(),
            });
        };
        // Check block heights are consecutive
        if block_header.height - 1 != previous_light_client_proof_output.da_block_height {
            return Err(anyhow!("Block heights are not consecutive"));
        }
        // Check prev hash matches with prev light client proof hash
        if block_header.prev_hash != previous_light_client_proof_output.da_block_hash {
            return Err(anyhow!(
                "Block prev hash does not match with prev light client proof hash"
            ));
        }
        // Skip hash, bits, pow and timestamp checks for now

        Ok(UpdatedDaState {
            hash: block_header.hash,
            height: block_header.height,
            total_work: [0; 32],
            epoch_start_time: 0,
            prev_11_timestamps: [0; 11],
            current_target_bits: 0,
        })
    }
}
