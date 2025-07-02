pub type L2BlockHash = [u8; 32];
pub type BlockNumber = u64;
pub type L2Range = (BlockNumber, BlockNumber);

#[derive(Copy, Clone, Debug)]
pub enum NodeType {
    Sequencer,
    FullNode,
    BatchProver,
    LightClientProver,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::BatchProver => write!(f, "batch-prover"),
            NodeType::Sequencer => write!(f, "sequencer"),
            NodeType::FullNode => write!(f, "full-node"),
            NodeType::LightClientProver => write!(f, "light-client-prover"),
        }
    }
}
