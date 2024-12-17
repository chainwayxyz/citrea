use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// TransientStorageContract wrapper.
sol! {
    #[sol(abi)]
    TransientStorage,
    "./src/evm/test_data/TransientStorage.abi"
}

/// TransientStorageContract wrapper.
pub struct TransientStorageContract {
    bytecode: Vec<u8>,
}

impl Default for TransientStorageContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/TransientStorage.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for TransientStorageContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl TransientStorageContract {
    /// TransientStorage bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Claims the gift.
    pub fn claim_gift(&self) -> Vec<u8> {
        TransientStorage::claimGiftCall {}.abi_encode()
    }
}
