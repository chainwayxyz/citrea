/// An enum representing the possible messages to send
/// from the RPC handler into the sequencer
pub enum SequencerRpcMessage {
    /// Produce a test block in the sequencer
    ProduceTestBlock,
    /// Halt sequencer commitments
    HaltCommitments,
    /// Resume sequencer commitments
    ResumeCommitments,
}
