use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// BlobBaseFeeContract wrapper.
sol! {
    #[sol(abi)]
    BlobBaseFee,
    "./src/evm/test_data/BlobBaseFee.abi"
}

/// BlobBaseFeeContract wrapper.
pub struct BlobBaseFeeContract {
    bytecode: Vec<u8>,
}

impl Default for BlobBaseFeeContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/BlobBaseFee.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for BlobBaseFeeContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl BlobBaseFeeContract {
    /// BlobBaseFee bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Store blobbasefee
    pub fn store_blob_base_fee(&self) -> Vec<u8> {
        BlobBaseFee::storeBlobBaseFeeCall {}.abi_encode()
    }
}
