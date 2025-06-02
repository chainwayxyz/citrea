use super::TestContract;

/// OneWeiReceiver wrapper.
pub struct OneWeiReceiverContract {
    bytecode: Vec<u8>,
}

impl Default for OneWeiReceiverContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/OneWeiReceiver.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for OneWeiReceiverContract {
    fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}
