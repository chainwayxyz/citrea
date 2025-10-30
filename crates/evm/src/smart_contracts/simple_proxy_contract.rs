use alloy_primitives::Address;
use alloy_sol_types::{sol, SolCall, SolConstructor};

use super::TestContract;

// SimpleProxy contract wrapper.
sol! {
    #[sol(abi)]
    SimpleProxy,
    "./src/evm/test_data/SimpleProxy.abi"
}

/// SimpleProxy contract wrapper.
pub struct SimpleProxyContract {
    bytecode: Vec<u8>,
}

impl Default for SimpleProxyContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../evm/test_data/SimpleProxy.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for SimpleProxyContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl SimpleProxyContract {
    /// SimpleProxy bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Construct the proxy with constructor argument (implementation address).
    pub fn construct(&self, implementation: Address) -> Vec<u8> {
        let mut bytecode = self.byte_code();
        bytecode.extend_from_slice(
            &SimpleProxy::constructorCall {
                _implementation: implementation,
            }
            .abi_encode(),
        );
        bytecode
    }

    /// Get deployment bytecode with constructor args (alias for construct).
    pub fn deployment_bytecode(&self, implementation: Address) -> Vec<u8> {
        self.construct(implementation)
    }

    /// This function always reverts and is used to test EIP-7702 gas estimation bug.
    pub fn reverting_execute_call_data(&self) -> Vec<u8> {
        SimpleProxy::revertingExecuteCall {
            _0: [0u8; 32].into(),
            _1: vec![].into(),
        }
        .abi_encode()
    }

    /// This function delegates to the implementation contract.
    pub fn execute_call_data(&self) -> Vec<u8> {
        SimpleProxy::executeCall {
            _0: [0u8; 32].into(),
            _1: vec![].into(),
        }
        .abi_encode()
    }

    /// This function delegates to the implementation contract with specific call data.
    pub fn execute_with_data_call_data(&self, nested_call_data: Vec<u8>) -> Vec<u8> {
        SimpleProxy::executeCall {
            _0: [0u8; 32].into(),
            _1: nested_call_data.into(),
        }
        .abi_encode()
    }
}
