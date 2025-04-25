use std::collections::HashMap;

use citrea_risc0_adapter::Digest;
use lazy_static::lazy_static;
use risc0_binfmt::compute_image_id;
use sov_rollup_interface::spec::SpecId;

macro_rules! guest {
    ($a:expr) => {{
        let code = include_bytes!($a).to_vec();
        let id = compute_image_id(&code).unwrap();

        (id, code)
    }};
}

lazy_static! {
    /// The following 2 are used as latest guest builds for tests that use mock DA.
    pub(crate) static ref BATCH_PROOF_LATEST_MOCK_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();

        m.insert(
            SpecId::Tangerine,
            (
                Digest::new(citrea_risc0_batch_proof::BATCH_PROOF_MOCK_ID),
                citrea_risc0_batch_proof::BATCH_PROOF_MOCK_ELF.to_vec(),
            ),
        );
        m
    };
    pub(crate) static ref LIGHT_CLIENT_LATEST_MOCK_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();

        m.insert(
            SpecId::Tangerine,
            (
                Digest::new(citrea_risc0_light_client::LIGHT_CLIENT_PROOF_MOCK_ID),
                citrea_risc0_light_client::LIGHT_CLIENT_PROOF_MOCK_ELF.to_vec(),
            )
        );
        m
    };

    pub(crate) static ref BATCH_PROOF_REGTEST_BITCOIN_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        HashMap::from(
            [
                (SpecId::Tangerine,
                    (Digest::new(citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
                    citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ELF.to_vec())
                )
            ]
        )
    };

    /// The following 2 are used as latest guest builds for tests that use Bitcoin DA.
    pub(crate) static ref BATCH_PROOF_LATEST_BITCOIN_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        HashMap::from(
            [
                (SpecId::Tangerine,
                    (Digest::new(citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
                    citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ELF.to_vec())
                )
            ]
        )
    };

    pub(crate) static ref LIGHT_CLIENT_LATEST_BITCOIN_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();

        m.insert(
            SpecId::Tangerine,
            (
                Digest::new(citrea_risc0_light_client::LIGHT_CLIENT_PROOF_BITCOIN_ID),
                citrea_risc0_light_client::LIGHT_CLIENT_PROOF_BITCOIN_ELF.to_vec(),
            )
        );
        m
    };
    /// Production guests
    pub(crate) static ref BATCH_PROOF_MAINNET_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();

        m.insert(SpecId::Tangerine, guest!("../../../resources/guests/risc0/mainnet/batch-0.elf"));
        m
    };
    pub(crate) static ref BATCH_PROOF_TESTNET_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();

        // won't be used but putting here just in case
        m.insert(SpecId::Genesis, guest!("../../../resources/guests/risc0/testnet/batch-proof-0.bin"));
        // won't be used but putting here just in case
        m.insert(SpecId::Kumquat, guest!("../../../resources/guests/risc0/testnet/batch-proof-0.bin"));
        m.insert(SpecId::Tangerine, guest!("../../../resources/guests/risc0/testnet/batch-proof-0.bin"));

        m
    };
    pub(crate) static ref BATCH_PROOF_DEVNET_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();

        // won't be used but putting here just in case
        m.insert(SpecId::Genesis, guest!("../../../resources/guests/risc0/devnet/batch-proof-0.bin"));
        // won't be used but putting here just in case
        m.insert(SpecId::Kumquat, guest!("../../../resources/guests/risc0/devnet/batch-proof-0.bin"));
        m.insert(SpecId::Tangerine, guest!("../../../resources/guests/risc0/devnet/batch-proof-0.bin"));

        m
    };
    pub(crate) static ref LIGHT_CLIENT_MAINNET_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();

        m.insert(SpecId::Tangerine, guest!("../../../resources/guests/risc0/mainnet/light-0.elf"));
        m
    };
    pub(crate) static ref LIGHT_CLIENT_TESTNET_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();

        // won't be used but putting here just in case
        m.insert(SpecId::Genesis, guest!("../../../resources/guests/risc0/testnet/light-client-proof-0.bin"));
        // won't be used but putting here just in case
        m.insert(SpecId::Kumquat, guest!("../../../resources/guests/risc0/testnet/light-client-proof-0.bin"));
        m.insert(SpecId::Tangerine, guest!("../../../resources/guests/risc0/testnet/light-client-proof-0.bin"));

        m
    };
    pub(crate) static ref LIGHT_CLIENT_DEVNET_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();

        // won't be used but putting here just in case
        m.insert(SpecId::Genesis, guest!("../../../resources/guests/risc0/devnet/light-client-proof-0.bin"));
        // won't be used but putting here just in case
        m.insert(SpecId::Kumquat, guest!("../../../resources/guests/risc0/devnet/light-client-proof-0.bin"));
        m.insert(SpecId::Tangerine, guest!("../../../resources/guests/risc0/devnet/light-client-proof-0.bin"));
        m
    };
}
