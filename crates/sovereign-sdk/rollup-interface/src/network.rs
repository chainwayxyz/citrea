use core::fmt::Display;

/// The network currently running.
#[derive(Copy, Clone, Default, Debug)]
pub enum Network {
    /// Mainnet
    #[default]
    Mainnet,
    /// Testnet
    Testnet,
    /// Devnet
    Devnet,
    /// Nightly
    Nightly,
}

impl Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Network {
    /// Constant function to get the Network from &str
    pub const fn const_from_str(s: &str) -> Option<Network> {
        match s.as_bytes() {
            b"mainnet" => Some(Network::Mainnet),
            b"testnet" => Some(Network::Testnet),
            b"devnet" => Some(Network::Devnet),
            b"nightly" => Some(Network::Nightly),
            _ => None,
        }
    }
}
