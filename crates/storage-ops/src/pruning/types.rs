#[derive(Copy, Clone)]
pub enum StorageNodeType {
    Sequencer,
    FullNode,
    BatchProver,
    LightClient,
}
