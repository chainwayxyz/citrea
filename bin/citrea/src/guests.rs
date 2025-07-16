use std::collections::HashMap;
use std::sync::LazyLock;

use citrea_risc0_adapter::Digest;
use risc0_binfmt::compute_image_id;
use sov_rollup_interface::spec::SpecId;

macro_rules! guest {
    ($a:expr) => {{
        let code = include_bytes!($a).to_vec();
        let id = compute_image_id(&code).unwrap();

        (id, code)
    }};
}

/// The following 2 are used as latest guest builds for tests that use mock DA.
pub(crate) static BATCH_PROOF_LATEST_MOCK_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();

        m.insert(
            SpecId::latest(),
            (
                Digest::new(citrea_risc0_batch_proof::BATCH_PROOF_MOCK_ID),
                citrea_risc0_batch_proof::BATCH_PROOF_MOCK_ELF.to_vec(),
            ),
        );
        m
    });

pub(crate) static LIGHT_CLIENT_LATEST_MOCK_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();

        m.insert(
            SpecId::latest(),
            (
                Digest::new(citrea_risc0_light_client::LIGHT_CLIENT_PROOF_MOCK_ID),
                citrea_risc0_light_client::LIGHT_CLIENT_PROOF_MOCK_ELF.to_vec(),
            ),
        );
        m
    });

pub(crate) static BATCH_PROOF_REGTEST_BITCOIN_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        HashMap::from([
            (
                SpecId::Tangerine,
                (
                    Digest::new(citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
                    citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ELF.to_vec(),
                ),
            ),
            (
                SpecId::latest(),
                (
                    Digest::new(citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
                    citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ELF.to_vec(),
                ),
            ),
        ])
    });

/// The following 2 are used as latest guest builds for tests that use Bitcoin DA.
pub(crate) static BATCH_PROOF_LATEST_BITCOIN_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        HashMap::from([(
            SpecId::latest(),
            (
                Digest::new(citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
                citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ELF.to_vec(),
            ),
        )])
    });

pub(crate) static LIGHT_CLIENT_LATEST_BITCOIN_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();

        m.insert(
            SpecId::latest(),
            (
                Digest::new(citrea_risc0_light_client::LIGHT_CLIENT_PROOF_BITCOIN_ID),
                citrea_risc0_light_client::LIGHT_CLIENT_PROOF_BITCOIN_ELF.to_vec(),
            ),
        );
        m
    });

/// Production guests
pub(crate) static BATCH_PROOF_MAINNET_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();

        m.insert(
            SpecId::Tangerine,
            guest!("../../../resources/guests/risc0/mainnet/batch-0.elf"),
        );
        m
    });

pub(crate) static BATCH_PROOF_TESTNET_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();

        // won't be used but putting here just in case
        m.insert(
            SpecId::Genesis,
            guest!("../../../resources/guests/risc0/testnet/batch-proof-0.bin"),
        );
        // won't be used but putting here just in case
        m.insert(
            SpecId::Kumquat,
            guest!("../../../resources/guests/risc0/testnet/batch-proof-0.bin"),
        );
        m.insert(
            SpecId::Tangerine,
            guest!("../../../resources/guests/risc0/testnet/batch-proof-0.bin"),
        );

        m
    });

pub(crate) static BATCH_PROOF_DEVNET_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();

        // won't be used but putting here just in case
        m.insert(
            SpecId::Genesis,
            guest!("../../../resources/guests/risc0/devnet/batch-proof-0.bin"),
        );
        // won't be used but putting here just in case
        m.insert(
            SpecId::Kumquat,
            guest!("../../../resources/guests/risc0/devnet/batch-proof-0.bin"),
        );
        m.insert(
            SpecId::Tangerine,
            guest!("../../../resources/guests/risc0/devnet/batch-proof-0.bin"),
        );

        m
    });

pub(crate) static LIGHT_CLIENT_MAINNET_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();

        m.insert(
            SpecId::Tangerine,
            guest!("../../../resources/guests/risc0/mainnet/light-0.elf"),
        );
        m
    });

pub(crate) static LIGHT_CLIENT_TESTNET_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();

        // won't be used but putting here just in case
        m.insert(
            SpecId::Genesis,
            guest!("../../../resources/guests/risc0/testnet/light-client-proof-0.bin"),
        );
        // won't be used but putting here just in case
        m.insert(
            SpecId::Kumquat,
            guest!("../../../resources/guests/risc0/testnet/light-client-proof-0.bin"),
        );
        m.insert(
            SpecId::Tangerine,
            guest!("../../../resources/guests/risc0/testnet/light-client-proof-0.bin"),
        );

        m
    });

pub(crate) static LIGHT_CLIENT_DEVNET_GUESTS: LazyLock<HashMap<SpecId, (Digest, Vec<u8>)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();

        // won't be used but putting here just in case
        m.insert(
            SpecId::Genesis,
            guest!("../../../resources/guests/risc0/devnet/light-client-proof-0.bin"),
        );
        // won't be used but putting here just in case
        m.insert(
            SpecId::Kumquat,
            guest!("../../../resources/guests/risc0/devnet/light-client-proof-0.bin"),
        );
        m.insert(
            SpecId::Tangerine,
            guest!("../../../resources/guests/risc0/devnet/light-client-proof-0.bin"),
        );
        m
    });
