#[derive(Copy, Clone, Debug)]
pub enum StorageNodeType {
    Sequencer,
    FullNode,
    BatchProver,
    LightClient,
}
