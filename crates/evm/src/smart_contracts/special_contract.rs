use alloy_primitives::Address;
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

sol! {
    #[sol(abi)]
    SpecialContract,
    "./src/evm/test_data/SpecialContract.abi"
}

/// SpecialContract wrapper - sets x=42, y=100 in constructor, has die() for selfdestruct.
pub struct SpecialContractContract {
    bytecode: Vec<u8>,
}

impl Default for SpecialContractContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/SpecialContract.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for SpecialContractContract {
    fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}

impl SpecialContractContract {
    /// SpecialContract bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Calls die(address payable to) to selfdestruct
    pub fn die(&self, to: Address) -> Vec<u8> {
        SpecialContract::dieCall { to }.abi_encode()
    }
}
