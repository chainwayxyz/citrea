use std::fmt::Display;

/// The network currently running.
#[derive(Copy, Clone, Default, Debug)]
pub enum Network {
    /// Mainnet
    #[default]
    Mainnet,
    /// Testnet
    Testnet,
    /// Testnet
    Devnet,
    /// nightly
    Nightly,
}

impl Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
