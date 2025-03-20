#![no_main]
use bitcoin_da::spec::BitcoinSpec;
use citrea_primitives::forks::{
    ALL_FORKS, DEVNET_FORKS, MAINNET_FORKS, NIGHTLY_FORKS, TESTNET_FORKS,
};
use citrea_risc0_adapter::guest::Risc0Guest;
use citrea_stf::runtime::CitreaRuntime;
use citrea_stf::verifier::StateTransitionVerifier;
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_api::fork::Fork;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;
use sov_state::ZkStorage;

risc0_zkvm::guest::entry!(main);

const NETWORK: Network = match option_env!("CITREA_NETWORK") {
    Some(network) => match Network::const_from_str(network) {
        Some(network) => network,
        None => panic!("Invalid CITREA_NETWORK value"),
    },
    None => Network::Nightly,
};

const SEQUENCER_PUBLIC_KEY: [u8; 33] = {
    let hex_pub_key = match NETWORK {
        Network::Mainnet => "000000000000000000000000000000000000000000000000000000000000000000",
        Network::Testnet => "0201edff3b3ee593dbef54e2fbdd421070db55e2de2aebe75f398bd85ac97ed364",
        Network::Devnet => "03745871636b11562a7f2d7c0e883a960b54c7e2c0a5427d4b99ac403588530589",
        Network::Nightly | Network::TestNetworkWithForks => {
            match option_env!("SEQUENCER_PUBLIC_KEY") {
                Some(hex_pub_key) => hex_pub_key,
                None => "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7",
            }
        }
    };

    match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("SEQUENCER_PUBLIC_KEY must be valid 33-byte hex string"),
    }
};

const FORKS: &[Fork] = match NETWORK {
    Network::Mainnet => &MAINNET_FORKS,
    Network::Testnet => &TESTNET_FORKS,
    Network::Devnet => &DEVNET_FORKS,
    Network::Nightly => &NIGHTLY_FORKS,
    Network::TestNetworkWithForks => &ALL_FORKS,
};

fn get_forks() -> &'static [Fork] {
    #[cfg(feature = "testing")]
    {
        if std::env::var("ALL_FORKS").is_ok() {
            println!("Enabling ALL_FORKS");
            return &ALL_FORKS;
        }
    }
    FORKS
}

pub fn main() {
    let guest = Risc0Guest::new();
    let storage = ZkStorage::new();
    let stf = StfBlueprint::new();

    let mut stf_verifier: StateTransitionVerifier<
        ZkDefaultContext,
        BitcoinSpec,
        CitreaRuntime<_, _>,
    > = StateTransitionVerifier::new(stf);

    let out = stf_verifier.run_sequencer_commitments_in_da_slot(
        &guest,
        storage,
        &SEQUENCER_PUBLIC_KEY,
        get_forks(),
    );

    guest.commit(&out);
}
