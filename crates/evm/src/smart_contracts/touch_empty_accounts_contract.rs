use alloy_primitives::Address;

use super::TestContract;

/// TouchEmptyAccountsContract wrapper.
pub struct TouchEmptyAccountsContract {
    bytecode: Vec<u8>,
}

impl Default for TouchEmptyAccountsContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex =
                include_str!("../../../evm/src/evm/test_data/TouchEmptyAccounts.bin").trim();
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for TouchEmptyAccountsContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl TouchEmptyAccountsContract {
    /// TouchEmptyAccounts bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Call data with 10 addresses (no function selector).
    pub fn touch_call_data(&self, addrs: &[Address; 10]) -> Vec<u8> {
        let mut data = Vec::with_capacity(10 * 32);
        for addr in addrs {
            data.extend_from_slice(&[0u8; 12]);
            data.extend_from_slice(addr.as_slice());
        }
        data
    }
}
