use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct LightClientCircuitOutput {
    pub state_root: [u8; 32],
}
