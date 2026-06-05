/// An enum representing the possible messages to send
/// from the RPC handler into the sequencer
pub enum SequencerRpcMessage {
    /// Produce a test block in the sequencer
    ProduceTestBlock,
    /// Halt sequencer commitments
    HaltCommitments,
    /// Resume sequencer commitments
    ResumeCommitments,
    /// Convert a listen-mode sequencer into a block-producing sequencer.
    ///
    /// Only handled by the listen-mode orchestrator. The `ack` channel is used to report the
    /// outcome of the conversion (e.g. success, or a reason it was rejected) back to the RPC
    /// caller.
    ConvertToProducer {
        /// Channel used to report the conversion outcome back to the RPC handler.
        ack: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}
