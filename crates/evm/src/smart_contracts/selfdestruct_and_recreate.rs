use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

sol! {
    #[sol(abi)]
    SelfdestructAndRecreate,
    "./src/evm/test_data/SelfdestructAndRecreate.abi"
}

/// SelfdestructAndRecreate wrapper - Contract A for test 2-a.
/// Calls selfdestruct on target, then asks factory to recreate.
pub struct SelfdestructAndRecreateContract {
    bytecode: Vec<u8>,
}

impl Default for SelfdestructAndRecreateContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex =
                include_str!("../../../evm/src/evm/test_data/SelfdestructAndRecreate.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for SelfdestructAndRecreateContract {
    fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}

impl SelfdestructAndRecreateContract {
    /// SelfdestructAndRecreate bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Calls destroyAndRecreate(address target, address beneficiary, address factory, bytes32 salt, bytes initCode)
    pub fn destroy_and_recreate(
        &self,
        target: Address,
        beneficiary: Address,
        factory: Address,
        salt: B256,
        init_code: Bytes,
    ) -> Vec<u8> {
        SelfdestructAndRecreate::destroyAndRecreateCall {
            target,
            beneficiary,
            factory,
            salt,
            initCode: init_code,
        }
        .abi_encode()
    }
}
