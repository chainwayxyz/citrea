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
        const fn const_compare_str(s1: &str, s2: &str) -> bool {
            let b1 = s1.as_bytes();
            let b2 = s2.as_bytes();
            if b1.len() != b2.len() {
                return false;
            }

            let mut i = 0;
            while i < b1.len() {
                if b1[i] != b2[i] {
                    return false;
                }
                i += 1;
            }

            true
        }

        if const_compare_str(s, "mainnet") {
            Some(Network::Mainnet)
        } else if const_compare_str(s, "testnet") {
            Some(Network::Testnet)
        } else if const_compare_str(s, "devnet") {
            Some(Network::Devnet)
        } else if const_compare_str(s, "nightly") {
            Some(Network::Nightly)
        } else {
            None
        }
    }
}
