use derive_more::Display;

#[derive(Copy, Clone, Display)]
pub enum StorageNodeType {
    Sequencer,
    FullNode,
    BatchProver,
    LightClient,
}
