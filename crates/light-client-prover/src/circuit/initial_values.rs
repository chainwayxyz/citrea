#[cfg(feature = "native")]
use bitcoin_da::spec::BitcoinSpec;
#[cfg(feature = "native")]
use sov_mock_da::MockDaSpec;
#[cfg(feature = "native")]
use sov_modules_api::DaSpec;
#[cfg(feature = "native")]
use sov_rollup_interface::Network;

#[cfg(feature = "native")]
use self::non_empty_slice::NonEmptySlice;

/// Genesis root for the Light Client Prover's Jellyfish Merkle Tree.
pub(crate) const LCP_JMT_GENESIS_ROOT: [u8; 32] = match const_hex::const_decode_to_array(
    b"5350415253455f4d45524b4c455f504c414345484f4c4445525f484153485f5f",
) {
    Ok(root) => root,
    Err(_) => panic!("LCP_JMT_GENESIS_ROOT must deserialize"),
};

/// Constant function to decode a hex string into a fixed-size array of u32.
const fn decode_to_u32_array(hex: &str) -> [u32; 8] {
    let bytes = const_hex::const_decode_to_array::<32>(hex.as_bytes());
    match bytes {
        Ok(decoded) => constmuck::cast(decoded),
        Err(_) => panic!("Invalid hex input"), // Replace with compile-time valid fallback if needed
    }
}

/// Module containing initial values for the mock DA specification.
pub mod mockda {
    use super::non_empty_slice::NonEmptySlice;

    /// Genesis L2 genesis root for the mock DA.
    pub const GENESIS_ROOT: [u8; 32] = match const_hex::const_decode_to_array(
        b"658e15edbc2b4168ac974778a2b516955589122d1a8309a7aa5afe8e22647c18",
    ) {
        Ok(root) => root,
        Err(_) => panic!("Can't happen"),
    };

    /// Initial batch proof method IDs for the mock DA.
    pub const INITIAL_BATCH_PROOF_METHOD_IDS: NonEmptySlice<(u64, [u32; 8])> =
        NonEmptySlice::new(&[(0, citrea_risc0_batch_proof::BATCH_PROOF_MOCK_ID)]);

    /// Public key of the batch prover in the mock DA.
    pub const BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"03eedab888e45f3bdc3ec9918c491c11e5cf7af0a91f38b97fbc1e135ae4056601",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("Can't happen"),
    };

    /// Public key of the sequencer in the mock DA.
    pub const SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("Can't happen"),
    };

    /// Public key of the method ID upgrade authority in the mock DA.
    pub const METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] =
        match const_hex::const_decode_to_array(
            b"0313c4ff65eb94999e0ac41cfe21592baa52910f5a5ada9074b816de4f560189db",
        ) {
            Ok(pub_key) => pub_key,
            Err(_) => panic!("Can't happen"),
        };
}

/// Module containing initial values for the Bitcoin DA (Data Availability) specification.
pub mod bitcoinda {
    use super::decode_to_u32_array;
    use super::non_empty_slice::NonEmptySlice;

    /// Genesis L2 root for the Bitcoin DA on Mainnet.
    pub const MAINNET_GENESIS_ROOT: [u8; 32] = match const_hex::const_decode_to_array(
        b"0000000000000000000000000000000000000000000000000000000000000000",
    ) {
        Ok(root) => root,
        Err(_) => panic!("Can't happen"),
    };

    /// Genesis L2 root for the Bitcoin DA on Testnet.
    pub const TESTNET_GENESIS_ROOT: [u8; 32] = match const_hex::const_decode_to_array(
        b"8292a2b07f40f9cee43fde4523567faab5261b1c1cf79ae56e1b4ef4b323735f",
    ) {
        Ok(root) => root,
        Err(_) => panic!("Can't happen"),
    };

    /// Genesis L2 root for the Bitcoin DA on Devnet.
    pub const DEVNET_GENESIS_ROOT: [u8; 32] = match const_hex::const_decode_to_array(
        b"ee72838efc878217d4a8150828f19afa9e58c3270269413a3c757aeddbad05a6",
    ) {
        Ok(root) => root,
        Err(_) => panic!("Can't happen"),
    };

    /// Genesis L2 root for the Bitcoin DA on Nightly.
    /// This root is set at compile time via the `L2_GENESIS_ROOT` environment variable.
    /// If the variable is not set, it defaults to the genesis root from the
    /// genesis config under resources/genesis/bitcoin-regtest.
    pub const NIGHTLY_GENESIS_ROOT: [u8; 32] = {
        let hex_root = match option_env!("L2_GENESIS_ROOT") {
            Some(hex_root) => hex_root,
            None => "2aa61219ad6eca9c511b2e360d2e74d084f0a2a52859954a5dd7cfd38eef4868",
        };

        match const_hex::const_decode_to_array(hex_root.as_bytes()) {
            Ok(root) => root,
            Err(_) => panic!("L2_GENESIS_ROOT must be valid 32-byte hex string"),
        }
    };

    /// Genesis LCP root for the Bitcoin DA on Test Network with Forks.
    /// This root is set at compile time via the `L2_GENESIS_ROOT` environment variable.
    /// If the variable is not set, it defaults to the genesis root from the
    /// genesis config under resources/genesis/bitcoin-regtest.
    pub const TEST_NETWORK_WITH_FORKS_GENESIS_ROOT: [u8; 32] = {
        let hex_root = match option_env!("L2_GENESIS_ROOT") {
            Some(hex_root) => hex_root,
            None => "2aa61219ad6eca9c511b2e360d2e74d084f0a2a52859954a5dd7cfd38eef4868",
        };

        match const_hex::const_decode_to_array(hex_root.as_bytes()) {
            Ok(root) => root,
            Err(_) => panic!("L2_GENESIS_ROOT must be valid 32-byte hex string"),
        }
    };

    /// Initial batch proof method IDs for the Bitcoin DA on Mainnet.
    pub const MAINNET_INITIAL_BATCH_PROOF_METHOD_IDS: NonEmptySlice<(u64, [u32; 8])> =
        NonEmptySlice::new(&[(0, [0; 8])]);

    /// Initial batch proof method IDs for the Bitcoin DA on Testnet.
    pub const TESTNET_INITIAL_BATCH_PROOF_METHOD_IDS: NonEmptySlice<(u64, [u32; 8])> =
        NonEmptySlice::new(&[(
            0,
            decode_to_u32_array("8d94f41179bbcd57066dadfdc4922a34fea4f32f1ec1ba7ca82c8c644f437013"),
        )]);

    /// Initial batch proof method IDs for the Bitcoin DA on Devnet.
    pub const DEVNET_INITIAL_BATCH_PROOF_METHOD_IDS: NonEmptySlice<(u64, [u32; 8])> =
        NonEmptySlice::new(&[(
            0,
            decode_to_u32_array("1c13e18cd83c22eba3f620e8619af49363b240de764f37501fac5d65047146ca"),
        )]);

    /// Initial batch proof method IDs for the Bitcoin DA on Nightly.
    /// This method ID is set at compile time via the `BATCH_PROOF_METHOD_ID` environment variable.
    /// If the variable is not set, it defaults to the method ID from the guest compilation via the `citrea_risc0_batch_proof` crate.
    /// Method IDs are paired with activation height 0.
    pub const NIGHTLY_INITIAL_BATCH_PROOF_METHOD_IDS: NonEmptySlice<(u64, [u32; 8])> = {
        const METHOD_IDS: &[(u64, [u32; 8])] = match option_env!("BATCH_PROOF_METHOD_ID") {
            Some(hex_method_id) => &[(0, decode_to_u32_array(hex_method_id))],
            None => &[(0, citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID)],
        };
        NonEmptySlice::new(METHOD_IDS)
    };
    /// Initial batch proof method IDs for the Bitcoin DA on Test Network with Forks.
    /// This method ID is set at compile time via the `BATCH_PROOF_METHOD_ID` environment variable, paired with activation height 0.
    /// If the variable is not set, the method ID from the guest compilation is appended to the predefined method IDs.
    pub const TEST_NETWORK_WITH_FORKS_INITIAL_BATCH_PROOF_METHOD_IDS: NonEmptySlice<(
        u64,
        [u32; 8],
    )> = {
        const METHOD_IDS: &[(u64, [u32; 8])] = match option_env!("BATCH_PROOF_METHOD_ID") {
            Some(hex_method_id) => &[(0, decode_to_u32_array(hex_method_id))],
            None => &[
                (
                    0,
                    decode_to_u32_array(
                        "382a4e434d1b4b0912604a9de8876e75ff7603680c90107d78f6f71784ef1922",
                    ),
                ),
                (
                    100,
                    decode_to_u32_array(
                        "7d28b6b03836af95eedd4c0aedfe93ed89d28356f0714dd01009a0b892585c03",
                    ),
                ),
                (100, citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
                (200, citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
            ],
        };
        NonEmptySlice::new(METHOD_IDS)
    };

    /// Public key of the batch prover in the Bitcoin DA on Mainnet.
    pub const MAINNET_BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"030000000000000000000000000000000000000000000000000000000000000000",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("PROVER_DA_PUB_KEY must be valid 33-byte hex string"),
    };

    /// Public key of the batch prover in the Bitcoin DA on Testnet.
    pub const TESTNET_BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"0357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a42",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("PROVER_DA_PUB_KEY must be valid 33-byte hex string"),
    };

    /// Public key of the batch prover in the Bitcoin DA on Devnet.
    pub const DEVNET_BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"03fc6fb2ef68368009c895d2d4351dcca4109ec2f5f327291a0553570ce769f5e5",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("PROVER_DA_PUB_KEY must be valid 33-byte hex string"),
    };

    /// Public key of the batch prover in the Bitcoin DA on Nightly.
    /// This public key is set at compile time via the `PROVER_DA_PUB_KEY` environment variable.
    /// If the variable is not set, it defaults to the public key from the config under resources/configs/bitcoin-regtest.
    pub const NIGHTLY_BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = {
        let hex_pub_key = match option_env!("PROVER_DA_PUB_KEY") {
            Some(hex_pub_key) => hex_pub_key,
            None => "03eedab888e45f3bdc3ec9918c491c11e5cf7af0a91f38b97fbc1e135ae4056601",
        };

        match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
            Ok(pub_key) => pub_key,
            Err(_) => panic!("PROVER_DA_PUB_KEY must be valid 33-byte hex string"),
        }
    };

    /// Public key of the batch prover in the Bitcoin DA on Test Network with Forks.
    /// This public key is set at compile time via the `PROVER_DA_PUB_KEY` environment variable.
    /// If the variable is not set, it defaults to the public key from the config under resources/configs/bitcoin-regtest.
    pub const TEST_NETWORK_WITH_FORKS_BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = {
        let hex_pub_key = match option_env!("PROVER_DA_PUB_KEY") {
            Some(hex_pub_key) => hex_pub_key,
            None => "03eedab888e45f3bdc3ec9918c491c11e5cf7af0a91f38b97fbc1e135ae4056601",
        };

        match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
            Ok(pub_key) => pub_key,
            Err(_) => panic!("SEQUENCER_DA_PUB_KEY must be valid 33-byte hex string"),
        }
    };

    /// Public key of the sequencer in the Bitcoin DA on Mainnet.
    pub const MAINNET_SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"030000000000000000000000000000000000000000000000000000000000000000",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("SEQUENCER_DA_PUB_KEY must be valid 33-byte hex string"),
    };

    /// Public key of the sequencer in the Bitcoin DA on Testnet.
    pub const TESTNET_SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"03015a7c4d2cc1c771198686e2ebef6fe7004f4136d61f6225b061d1bb9b821b9b",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("SEQUENCER_DA_PUB_KEY must be valid 33-byte hex string"),
    };

    /// Public key of the sequencer in the Bitcoin DA on Devnet.
    pub const DEVNET_SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"039cd55f9b3dcf306c4d54f66cd7c4b27cc788632cd6fb73d80c99d303c6536486",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("SEQUENCER_DA_PUB_KEY must be valid 33-byte hex string"),
    };

    /// Public key of the sequencer in the Bitcoin DA on Nightly.
    /// This public key is set at compile time via the `SEQUENCER_DA_PUB_KEY` environment variable.
    /// If the variable is not set, it defaults to the public key from the config under resources/configs/bitcoin-regtest.
    pub const NIGHTLY_SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = {
        let hex_pub_key = match option_env!("SEQUENCER_DA_PUB_KEY") {
            Some(hex_pub_key) => hex_pub_key,
            None => "02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9",
        };

        match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
            Ok(pub_key) => pub_key,
            Err(_) => panic!("SEQUENCER_DA_PUB_KEY must be valid 33-byte hex string"),
        }
    };

    /// Public key of the sequencer in the Bitcoin DA on Test Network with Forks.
    /// This public key is set at compile time via the `SEQUENCER_DA_PUB_KEY environment variable.
    /// If the variable is not set, it defaults to the public key from the config under resources/configs/bitcoin-regtest.
    pub const TEST_NETWORK_WITH_FORKS_SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = {
        let hex_pub_key = match option_env!("SEQUENCER_DA_PUB_KEY") {
            Some(hex_pub_key) => hex_pub_key,
            None => "02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9",
        };

        match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
            Ok(pub_key) => pub_key,
            Err(_) => panic!("SEQUENCER_DA_PUB_KEY must be valid 33-byte hex string"),
        }
    };

    /// Public key of the method ID upgrade authority in the Bitcoin DA on Mainnet.
    pub const MAINNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] =
        match const_hex::const_decode_to_array(
            b"000000000000000000000000000000000000000000000000000000000000000000",
        ) {
            Ok(pub_key) => pub_key,
            Err(_) => {
                panic!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY must be valid 33-byte hex string")
            }
        };

    /// Public key of the method ID upgrade authority in the Bitcoin DA on Testnet.
    pub const TESTNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] =
        match const_hex::const_decode_to_array(
            b"03796a3a8a86ff1cc37437585f0450f6059c397c01bce06bfbaaa36242f7ebfc02",
        ) {
            Ok(pub_key) => pub_key,
            Err(_) => {
                panic!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY must be valid 33-byte hex string")
            }
        };

    /// Public key of the method ID upgrade authority in the Bitcoin DA on Devnet.
    pub const DEVNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] =
        match const_hex::const_decode_to_array(
            b"0388e988066db18e19750fa92aa0fbf9c85104be2b5b507ce0aa7f30f3fe24b1ac",
        ) {
            Ok(pub_key) => pub_key,
            Err(_) => {
                panic!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY must be valid 33-byte hex string")
            }
        };

    /// Public key of the method ID upgrade authority in the Bitcoin DA on Nightly.
    /// This public key is set at compile time via the `METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY` environment variable.
    /// If the variable is not set, it defaults to a predefined value.
    pub const NIGHTLY_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] = {
        let hex_pub_key = match option_env!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY") {
            Some(hex_pub_key) => hex_pub_key,
            None => "0313c4ff65eb94999e0ac41cfe21592baa52910f5a5ada9074b816de4f560189db",
        };

        match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
            Ok(pub_key) => pub_key,
            Err(_) => {
                panic!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY must be valid 33-byte hex string")
            }
        }
    };

    /// Public key of the method ID upgrade authority in the Bitcoin DA on Test Network with Forks.
    /// This public key is set at compile time via the `METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY` environment variable.
    /// If the variable is not set, it defaults to a predefined value.
    pub const TEST_NETWORK_WITH_FORKS_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] = {
        let hex_pub_key = match option_env!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY") {
            Some(hex_pub_key) => hex_pub_key,
            None => "0313c4ff65eb94999e0ac41cfe21592baa52910f5a5ada9074b816de4f560189db",
        };

        match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
            Ok(pub_key) => pub_key,
            Err(_) => {
                panic!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY must be valid 33-byte hex string")
            }
        }
    };
}

/// Trait to provide initial values for the Light Client circuit based on the Data Availability specification.
#[cfg(feature = "native")]
pub trait InitialValueProvider<Das: DaSpec> {
    /// Returns the L2 genesis root
    fn get_l2_genesis_root(&self) -> [u8; 32];

    /// Returns the initial batch proof method IDs.
    fn initial_batch_proof_method_ids(&self) -> NonEmptySlice<(u64, [u32; 8])>;

    /// Returns the public key of the batch prover.
    fn batch_prover_da_public_key(&self) -> [u8; 33];

    /// Returns the public key of the sequencer.
    fn sequencer_da_public_key(&self) -> [u8; 33];

    /// Returns the public key of the method ID upgrade authority.
    fn method_id_upgrade_authority_da_public_key(&self) -> [u8; 33];
}

#[cfg(feature = "native")]
impl InitialValueProvider<MockDaSpec> for Network {
    fn get_l2_genesis_root(&self) -> [u8; 32] {
        assert_eq!(self, &Network::Nightly, "Only nightly allowed on mock da!");
        mockda::GENESIS_ROOT
    }

    fn initial_batch_proof_method_ids(&self) -> NonEmptySlice<(u64, [u32; 8])> {
        assert_eq!(self, &Network::Nightly, "Only nightly allowed on mock da!");
        mockda::INITIAL_BATCH_PROOF_METHOD_IDS
    }

    fn batch_prover_da_public_key(&self) -> [u8; 33] {
        assert_eq!(self, &Network::Nightly, "Only nightly allowed on mock da!");
        mockda::BATCH_PROVER_DA_PUBLIC_KEY
    }

    fn method_id_upgrade_authority_da_public_key(&self) -> [u8; 33] {
        assert_eq!(self, &Network::Nightly, "Only nightly allowed on mock da!");
        mockda::METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY
    }

    fn sequencer_da_public_key(&self) -> [u8; 33] {
        assert_eq!(self, &Network::Nightly, "Only nightly allowed on mock da!");
        mockda::SEQUENCER_DA_PUBLIC_KEY
    }
}

#[cfg(feature = "native")]
impl InitialValueProvider<BitcoinSpec> for Network {
    fn get_l2_genesis_root(&self) -> [u8; 32] {
        match self {
            Network::Mainnet => bitcoinda::MAINNET_GENESIS_ROOT,
            Network::Testnet => bitcoinda::TESTNET_GENESIS_ROOT,
            Network::Devnet => bitcoinda::DEVNET_GENESIS_ROOT,
            Network::Nightly => bitcoinda::NIGHTLY_GENESIS_ROOT,
            Network::TestNetworkWithForks => bitcoinda::TEST_NETWORK_WITH_FORKS_GENESIS_ROOT,
        }
    }

    fn initial_batch_proof_method_ids(&self) -> NonEmptySlice<(u64, [u32; 8])> {
        match self {
            Network::Mainnet => bitcoinda::MAINNET_INITIAL_BATCH_PROOF_METHOD_IDS,
            Network::Testnet => bitcoinda::TESTNET_INITIAL_BATCH_PROOF_METHOD_IDS,
            Network::Devnet => bitcoinda::DEVNET_INITIAL_BATCH_PROOF_METHOD_IDS,
            Network::Nightly => bitcoinda::NIGHTLY_INITIAL_BATCH_PROOF_METHOD_IDS,
            Network::TestNetworkWithForks => {
                bitcoinda::TEST_NETWORK_WITH_FORKS_INITIAL_BATCH_PROOF_METHOD_IDS
            }
        }
    }

    fn batch_prover_da_public_key(&self) -> [u8; 33] {
        match self {
            Network::Mainnet => bitcoinda::MAINNET_BATCH_PROVER_DA_PUBLIC_KEY,
            Network::Testnet => bitcoinda::TESTNET_BATCH_PROVER_DA_PUBLIC_KEY,
            Network::Devnet => bitcoinda::DEVNET_BATCH_PROVER_DA_PUBLIC_KEY,
            Network::Nightly => bitcoinda::NIGHTLY_BATCH_PROVER_DA_PUBLIC_KEY,
            Network::TestNetworkWithForks => {
                bitcoinda::TEST_NETWORK_WITH_FORKS_BATCH_PROVER_DA_PUBLIC_KEY
            }
        }
    }

    fn method_id_upgrade_authority_da_public_key(&self) -> [u8; 33] {
        match self {
            Network::Mainnet => bitcoinda::MAINNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
            Network::Testnet => bitcoinda::TESTNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
            Network::Devnet => bitcoinda::DEVNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
            Network::Nightly => bitcoinda::NIGHTLY_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
            Network::TestNetworkWithForks => {
                bitcoinda::TEST_NETWORK_WITH_FORKS_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY
            }
        }
    }

    fn sequencer_da_public_key(&self) -> [u8; 33] {
        match self {
            Network::Mainnet => bitcoinda::MAINNET_SEQUENCER_DA_PUBLIC_KEY,
            Network::Testnet => bitcoinda::TESTNET_SEQUENCER_DA_PUBLIC_KEY,
            Network::Devnet => bitcoinda::DEVNET_SEQUENCER_DA_PUBLIC_KEY,
            Network::Nightly => bitcoinda::NIGHTLY_SEQUENCER_DA_PUBLIC_KEY,
            Network::TestNetworkWithForks => {
                bitcoinda::TEST_NETWORK_WITH_FORKS_SEQUENCER_DA_PUBLIC_KEY
            }
        }
    }
}

/// Module for NonEmptySlice, so that it cannot be constructed like `NonEmptySlice(&[])`.
pub mod non_empty_slice {
    /// A wrapper around a slice to ensure that it is never empty.
    pub struct NonEmptySlice<'a, T>(&'a [T]);
    impl<'a, T> NonEmptySlice<'a, T> {
        /// Creates a new `NonEmptySlice` from a slice, ensuring that the slice is not empty.
        pub const fn new(slice: &'a [T]) -> Self {
            assert!(!slice.is_empty(), "Empty slice passed to NonEmptySlice");
            Self(slice)
        }

        /// Returns the inner slice.
        pub const fn inner(&self) -> &'a [T] {
            self.0
        }

        /// Converts the `NonEmptySlice` to a vector, cloning the elements.
        pub fn to_vec(&self) -> Vec<T>
        where
            T: Clone,
        {
            self.inner().to_vec()
        }
    }

    #[test]
    fn test_non_empty_slice() {
        // Test with a non-empty slice
        let slice = NonEmptySlice::new(&[1, 2, 3]);
        assert_eq!(slice.inner(), &[1, 2, 3]);
        assert_eq!(slice.to_vec(), vec![1, 2, 3]);

        // Test with an empty slice
        let result = std::panic::catch_unwind(|| {
            let _empty_slice: NonEmptySlice<u32> = NonEmptySlice::new(&[]);
        });
        assert!(result.is_err());
    }
}
