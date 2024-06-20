use serde::Deserialize;

/// Runner configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RunnerConfig {
    /// Sequencer client configuration.
    pub sequencer_client_url: String,
    /// Saves sequencer soft batches if set to true
    pub include_tx_body: bool,
    /// Only true for tests
    pub accept_public_input_as_proven: Option<bool>,
}

/// RPC configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct UtilityServerConfig {
    /// Http host.
    pub bind_host: String,
    /// Http port.
    pub bind_port: u16,
}
