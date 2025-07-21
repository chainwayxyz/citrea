use sov_rollup_interface::Network;

/// Allow dev mode usage for proof verification, only in testing or dev networks.
/// So we return false for mainnet and true for all other networks.
pub fn network_to_dev_mode(network: Network) -> bool {
    !matches!(network, Network::Mainnet)
}

#[test]
fn test_network_to_dev_mode() {
    assert!(network_to_dev_mode(Network::Testnet));
    assert!(network_to_dev_mode(Network::Devnet));
    assert!(network_to_dev_mode(Network::Nightly));
    assert!(network_to_dev_mode(Network::TestNetworkWithForks));

    assert!(!network_to_dev_mode(Network::Mainnet));
}
