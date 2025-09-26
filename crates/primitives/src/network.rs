pub fn citrea_network_to_method_id_upgrade_identifier(
    network: sov_rollup_interface::Network,
) -> u8 {
    match network {
        sov_rollup_interface::Network::Mainnet => 0,
        sov_rollup_interface::Network::Testnet => 1,
        sov_rollup_interface::Network::Devnet => 2,
        sov_rollup_interface::Network::Nightly => 3,
        sov_rollup_interface::Network::TestNetworkWithForks => 4,
    }
}
