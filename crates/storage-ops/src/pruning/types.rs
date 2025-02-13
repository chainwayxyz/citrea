#[derive(Copy, Clone)]
pub enum PruningNodeType {
    Sequencer,
    FullNode,
    BatchProver,
    LightClient,
}
