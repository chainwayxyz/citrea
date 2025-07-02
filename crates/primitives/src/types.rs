use derive_more::Display;

pub type L2BlockHash = [u8; 32];
pub type BlockNumber = u64;
pub type L2Range = (BlockNumber, BlockNumber);

#[derive(Copy, Clone, Debug, Display)]
pub enum NodeType {
    Sequencer,
    FullNode,
    BatchProver,
    LightClientProver,
}
