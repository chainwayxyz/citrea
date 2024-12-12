use alloy_primitives::Address;
use alloy_sol_types::{sol, SolConstructor};

use super::TestContract;

// SelfdestructingConstructorContract wrapper.
sol! {
    #[sol(abi)]
    SelfdestructingConstructor,
    "./src/evm/test_data/SelfdestructingConstructor.abi"
}

/// SelfdestructingConstructorContract wrapper.
pub struct SelfdestructingConstructorContract {
    bytecode: Vec<u8>,
}

impl Default for SelfdestructingConstructorContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex =
                include_str!("../../../evm/src/evm/test_data/SelfdestructingConstructor.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for SelfdestructingConstructorContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl SelfdestructingConstructorContract {
    /// SelfdestructingConstructor bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Claims the gift.
    pub fn construct(&self, recipient: Address) -> Vec<u8> {
        let mut v = self.byte_code();

        v.extend_from_slice(
            &SelfdestructingConstructor::constructorCall { recipient }.abi_encode(),
        );

        v
    }
}
