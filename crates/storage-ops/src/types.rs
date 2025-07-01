use derive_more::Display;

#[derive(Copy, Clone, Debug, Display)]
pub enum StorageNodeType {
    Sequencer,
    FullNode,
    BatchProver,
    LightClient,
}

#[derive(Copy, Clone, Debug)]
pub enum NodeKind {
    Sequencer,
    FullNode,
    BatchProver,
    LightClientProver,
}

impl std::fmt::Display for NodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeKind::BatchProver => write!(f, "batch-prover"),
            NodeKind::Sequencer => write!(f, "sequencer"),
            NodeKind::FullNode => write!(f, "full-node"),
            NodeKind::LightClientProver => write!(f, "light-client-prover"),
        }
    }
}
