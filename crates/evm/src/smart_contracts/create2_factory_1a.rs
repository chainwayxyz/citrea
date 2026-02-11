use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

sol! {
    #[sol(abi)]
    Create2Factory1a,
    "./src/evm/test_data/Create2Factory1a.abi"
}

/// Create2Factory1a wrapper - creates, calls selfdestruct, recreates in one tx.
pub struct Create2Factory1aContract {
    bytecode: Vec<u8>,
}

impl Default for Create2Factory1aContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Create2Factory1a.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for Create2Factory1aContract {
    fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}

impl Create2Factory1aContract {
    /// Create2Factory1a bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Calls deployDestroyRedeploy(bytes32 salt, bytes initCode, address beneficiary)
    pub fn deploy_destroy_redeploy(
        &self,
        salt: B256,
        init_code: Bytes,
        beneficiary: Address,
    ) -> Vec<u8> {
        Create2Factory1a::deployDestroyRedeployCall {
            salt,
            initCode: init_code,
            beneficiary,
        }
        .abi_encode()
    }

    /// Computes the CREATE2 address for given factory, salt, and init code
    pub fn compute_address(factory: Address, salt: B256, init_code: &[u8]) -> Address {
        let init_code_hash = alloy_primitives::keccak256(init_code);
        factory.create2(salt, init_code_hash)
    }
}
