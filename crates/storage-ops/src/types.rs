use derive_more::Display;

#[derive(Copy, Clone, Debug, Display)]
pub enum StorageNodeType {
    Sequencer,
    FullNode,
    BatchProver,
    LightClient,
}
