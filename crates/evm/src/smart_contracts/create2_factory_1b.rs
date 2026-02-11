use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

sol! {
    #[sol(abi)]
    Create2Factory1b,
    "./src/evm/test_data/Create2Factory1b.abi"
}

/// Create2Factory1b wrapper - has deployAndDestroy + deployOnly functions.
pub struct Create2Factory1bContract {
    bytecode: Vec<u8>,
}

impl Default for Create2Factory1bContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Create2Factory1b.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for Create2Factory1bContract {
    fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}

impl Create2Factory1bContract {
    /// Create2Factory1b bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Calls deployAndDestroy(bytes32 salt, bytes initCode, address beneficiary)
    pub fn deploy_and_destroy(
        &self,
        salt: B256,
        init_code: Bytes,
        beneficiary: Address,
    ) -> Vec<u8> {
        Create2Factory1b::deployAndDestroyCall {
            salt,
            initCode: init_code,
            beneficiary,
        }
        .abi_encode()
    }

    /// Calls deployOnly(bytes32 salt, bytes initCode)
    pub fn deploy_only(&self, salt: B256, init_code: Bytes) -> Vec<u8> {
        Create2Factory1b::deployOnlyCall {
            salt,
            initCode: init_code,
        }
        .abi_encode()
    }

    /// Computes the CREATE2 address for given factory, salt, and init code
    pub fn compute_address(factory: Address, salt: B256, init_code: &[u8]) -> Address {
        let init_code_hash = alloy_primitives::keccak256(init_code);
        factory.create2(salt, init_code_hash)
    }
}
