use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolCall, SolConstructor};

use super::TestContract;

// ERC20Implementation contract wrapper
sol! {
    #[sol(abi)]
    ERC20Implementation,
    "./src/evm/test_data/ERC20Implementation.abi"
}

// SimpleTokenProxy contract wrapper
sol! {
    #[sol(abi)]
    SimpleTokenProxy,
    "./src/evm/test_data/SimpleTokenProxy.abi"
}

/// ERC20Implementation contract wrapper - the implementation contract
pub struct ERC20ImplementationContract {
    bytecode: Vec<u8>,
}

impl Default for ERC20ImplementationContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../evm/test_data/ERC20Implementation.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for ERC20ImplementationContract {
    fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}

impl ERC20ImplementationContract {
    /// Get bytecode
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Get call data for approve function
    pub fn approve_call_data(&self, spender: Address, amount: U256) -> Vec<u8> {
        ERC20Implementation::approveCall { spender, amount }.abi_encode()
    }

    /// Get call data for transfer function
    pub fn transfer_call_data(&self, to: Address, amount: U256) -> Vec<u8> {
        ERC20Implementation::transferCall { to, amount }.abi_encode()
    }
}

/// SimpleTokenProxy contract wrapper - the proxy that delegates to implementation
pub struct SimpleTokenProxyContract {
    bytecode: Vec<u8>,
}

impl Default for SimpleTokenProxyContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../evm/test_data/SimpleTokenProxy.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for SimpleTokenProxyContract {
    fn byte_code(&self) -> Vec<u8> {
        self.construct(Address::ZERO, U256::ZERO)
    }
}

impl SimpleTokenProxyContract {
    /// Get deployment bytecode with constructor args (implementation address, initial supply)
    pub fn construct(&self, implementation: Address, initial_supply: U256) -> Vec<u8> {
        let mut bytecode = self.bytecode.clone();
        bytecode.extend_from_slice(
            &SimpleTokenProxy::constructorCall {
                _implementation: implementation,
                initialSupply: initial_supply,
            }
            .abi_encode(),
        );
        bytecode
    }

    /// Get deployment bytecode with constructor args
    pub fn deployment_bytecode(&self, implementation: Address, initial_supply: U256) -> Vec<u8> {
        self.construct(implementation, initial_supply)
    }
}
