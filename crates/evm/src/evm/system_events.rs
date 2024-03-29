/// A system event is an event that is emitted on special conditions by the EVM.
/// There events will be transformed into Evm transactions and put in the begining of the block.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum SystemEvent {
    L1BlockHashInitialize(/*block number*/ u64),
    L1BlockHashSetBlockInfo(/*hash*/ [u8; 32], /*merkle root*/ [u8; 32]),
}
