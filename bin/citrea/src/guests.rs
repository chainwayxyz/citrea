use std::collections::HashMap;
use std::sync::LazyLock;

use citrea_sp1::ProgramVKeyHash;
use sov_rollup_interface::spec::SpecId;

// Production networks always use their committed guests, independently of
// CITREA_NETWORK and the local development guest build.
// One module per pinned guest version, written by tools/pin-sp1-guests.py.
#[path = "../../../resources/guests/sp1/devnet/batch-proof-0.rs"]
mod devnet_batch_proof_0;
#[path = "../../../resources/guests/sp1/devnet/light-client-proof-0.rs"]
mod devnet_light_client_proof_0;
#[path = "../../../resources/guests/sp1/mainnet/batch-proof-0.rs"]
mod mainnet_batch_proof_0;
#[path = "../../../resources/guests/sp1/mainnet/light-client-proof-0.rs"]
mod mainnet_light_client_proof_0;
#[path = "../../../resources/guests/sp1/testnet/batch-proof-0.rs"]
mod testnet_batch_proof_0;
#[path = "../../../resources/guests/sp1/testnet/light-client-proof-0.rs"]
mod testnet_light_client_proof_0;

macro_rules! guest {
    ($pin:ident) => {
        ($pin::ID, $pin::ELF.to_vec())
    };
}

/// The following 2 are used as latest guest builds for tests that use mock DA.
pub(crate) static BATCH_PROOF_LATEST_MOCK_GUESTS: LazyLock<
    HashMap<SpecId, (ProgramVKeyHash, Vec<u8>)>,
> = LazyLock::new(|| {
    let mut m = HashMap::new();

    m.insert(
        SpecId::latest(),
        (
            citrea_sp1_batch_proof::BATCH_PROOF_MOCK_ID,
            citrea_sp1_batch_proof::BATCH_PROOF_MOCK_ELF.to_vec(),
        ),
    );
    m
});

pub(crate) static LIGHT_CLIENT_LATEST_MOCK_GUESTS: LazyLock<
    HashMap<SpecId, (ProgramVKeyHash, Vec<u8>)>,
> = LazyLock::new(|| {
    let mut m = HashMap::new();

    m.insert(
        SpecId::latest(),
        (
            citrea_sp1_light_client::LIGHT_CLIENT_PROOF_MOCK_ID,
            citrea_sp1_light_client::LIGHT_CLIENT_PROOF_MOCK_ELF.to_vec(),
        ),
    );
    m
});

/// The following 2 are used as latest guest builds for tests that use Bitcoin DA.
pub(crate) static BATCH_PROOF_LATEST_BITCOIN_GUESTS: LazyLock<
    HashMap<SpecId, (ProgramVKeyHash, Vec<u8>)>,
> = LazyLock::new(|| {
    HashMap::from([(
        SpecId::latest(),
        (
            citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ID,
            citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ELF.to_vec(),
        ),
    )])
});

pub(crate) static LIGHT_CLIENT_LATEST_BITCOIN_GUESTS: LazyLock<
    HashMap<SpecId, (ProgramVKeyHash, Vec<u8>)>,
> = LazyLock::new(|| {
    let mut m = HashMap::new();

    m.insert(
        SpecId::latest(),
        (
            citrea_sp1_light_client::LIGHT_CLIENT_PROOF_BITCOIN_ID,
            citrea_sp1_light_client::LIGHT_CLIENT_PROOF_BITCOIN_ELF.to_vec(),
        ),
    );
    m
});

/// Production guests, one entry per fork. A fork that leaves a guest unchanged reuses the
/// previous fork's pin; a fork that changes it gets the next index.
/// SP1 proves everything after the RISC0 cutoff with V3's guests,
/// see `citrea_primitives::risc0_cutoff`
pub(crate) static BATCH_PROOF_MAINNET_GUESTS: LazyLock<
    HashMap<SpecId, (ProgramVKeyHash, Vec<u8>)>,
> = LazyLock::new(|| HashMap::from([(SpecId::Pomelo, guest!(mainnet_batch_proof_0))]));

pub(crate) static BATCH_PROOF_TESTNET_GUESTS: LazyLock<
    HashMap<SpecId, (ProgramVKeyHash, Vec<u8>)>,
> = LazyLock::new(|| HashMap::from([(SpecId::Pomelo, guest!(testnet_batch_proof_0))]));

pub(crate) static BATCH_PROOF_DEVNET_GUESTS: LazyLock<HashMap<SpecId, (ProgramVKeyHash, Vec<u8>)>> =
    LazyLock::new(|| HashMap::from([(SpecId::Pomelo, guest!(devnet_batch_proof_0))]));

pub(crate) static LIGHT_CLIENT_MAINNET_GUESTS: LazyLock<
    HashMap<SpecId, (ProgramVKeyHash, Vec<u8>)>,
> = LazyLock::new(|| HashMap::from([(SpecId::Pomelo, guest!(mainnet_light_client_proof_0))]));

pub(crate) static LIGHT_CLIENT_TESTNET_GUESTS: LazyLock<
    HashMap<SpecId, (ProgramVKeyHash, Vec<u8>)>,
> = LazyLock::new(|| HashMap::from([(SpecId::Pomelo, guest!(testnet_light_client_proof_0))]));

pub(crate) static LIGHT_CLIENT_DEVNET_GUESTS: LazyLock<
    HashMap<SpecId, (ProgramVKeyHash, Vec<u8>)>,
> = LazyLock::new(|| HashMap::from([(SpecId::Pomelo, guest!(devnet_light_client_proof_0))]));
