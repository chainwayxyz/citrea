#[cfg(feature = "native")]
use bitcoin_da::spec::BitcoinSpec;
#[cfg(feature = "native")]
use sov_mock_da::MockDaSpec;
#[cfg(feature = "native")]
use sov_modules_api::DaSpec;
#[cfg(feature = "native")]
use sov_rollup_interface::Network;

pub(crate) const LCP_JMT_GENESIS_ROOT: [u8; 32] = match const_hex::const_decode_to_array(
    b"5350415253455f4d45524b4c455f504c414345484f4c4445525f484153485f5f",
) {
    Ok(root) => root,
    Err(_) => panic!("LCP_JMT_GENESIS_ROOT must deserialize"),
};

const fn decode_to_u32_array(hex: &str) -> [u32; 8] {
    let bytes = const_hex::const_decode_to_array::<32>(hex.as_bytes());
    match bytes {
        Ok(decoded) => constmuck::cast(decoded),
        Err(_) => panic!("Invalid hex input"), // Replace with compile-time valid fallback if needed
    }
}

pub mod mockda {
    pub const GENESIS_ROOT: [u8; 32] = match const_hex::const_decode_to_array(
        b"f3a1164976f5f1d4c74779c58fea93e212a7fdea1745a7d3ef028d6bca834425",
    ) {
        Ok(root) => root,
        Err(_) => panic!("Can't happen"),
    };

    pub const INITIAL_BATCH_PROOF_METHOD_IDS: &[(u64, [u32; 8])] =
        &[(0, citrea_risc0_batch_proof::BATCH_PROOF_MOCK_ID)];

    pub const BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"03eedab888e45f3bdc3ec9918c491c11e5cf7af0a91f38b97fbc1e135ae4056601",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("Can't happen"),
    };

    pub const METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] =
        match const_hex::const_decode_to_array(
            b"0313c4ff65eb94999e0ac41cfe21592baa52910f5a5ada9074b816de4f560189db",
        ) {
            Ok(pub_key) => pub_key,
            Err(_) => panic!("Can't happen"),
        };
}

pub mod bitcoinda {
    use super::decode_to_u32_array;

    pub const MAINNET_GENESIS_ROOT: [u8; 32] = match const_hex::const_decode_to_array(
        b"0000000000000000000000000000000000000000000000000000000000000000",
    ) {
        Ok(root) => root,
        Err(_) => panic!("Can't happen"),
    };

    pub const TESTNET_GENESIS_ROOT: [u8; 32] = match const_hex::const_decode_to_array(
        b"b7a7fdf56aa1725049704457596db552f2e975e37b2a786cfabedf987c2e7e08",
    ) {
        Ok(root) => root,
        Err(_) => panic!("Can't happen"),
    };

    pub const DEVNET_GENESIS_ROOT: [u8; 32] = match const_hex::const_decode_to_array(
        b"7bc4a868439b637b57fcc55bf6e119e51996d6a4127a39f1393c8c1e29d37365",
    ) {
        Ok(root) => root,
        Err(_) => panic!("Can't happen"),
    };

    pub const NIGHTLY_GENESIS_ROOT: [u8; 32] = {
        let hex_root = match option_env!("L2_GENESIS_ROOT") {
            Some(hex_root) => hex_root,
            None => "f3a1164976f5f1d4c74779c58fea93e212a7fdea1745a7d3ef028d6bca834425",
        };

        match const_hex::const_decode_to_array(hex_root.as_bytes()) {
            Ok(root) => root,
            Err(_) => panic!("L2_GENESIS_ROOT must be valid 32-byte hex string"),
        }
    };

    pub const TEST_NETWORK_WITH_FORKS_GENESIS_ROOT: [u8; 32] = {
        let hex_root = match option_env!("L2_GENESIS_ROOT") {
            Some(hex_root) => hex_root,
            None => "f3a1164976f5f1d4c74779c58fea93e212a7fdea1745a7d3ef028d6bca834425",
        };

        match const_hex::const_decode_to_array(hex_root.as_bytes()) {
            Ok(root) => root,
            Err(_) => panic!("L2_GENESIS_ROOT must be valid 32-byte hex string"),
        }
    };

    pub const MAINNET_INITIAL_BATCH_PROOF_METHOD_IDS: &[(u64, [u32; 8])] = &[(0, [0; 8])];

    pub const TESTNET_INITIAL_BATCH_PROOF_METHOD_IDS: &[(u64, [u32; 8])] = &[
        (
            0,
            decode_to_u32_array("3631d90630a3f0deb47f3a3411fe6e7ede1b0d86ad4216c75041e1a2020f009f"),
        ),
        (
            5546000,
            decode_to_u32_array("670b7ef87e7fab2ff2d46f38f71be524d42cc0c62da41884d3d41928b8c967d1"),
        ),
    ];

    pub const DEVNET_INITIAL_BATCH_PROOF_METHOD_IDS: &[(u64, [u32; 8])] = &[
        (
            0,
            decode_to_u32_array("3631d90630a3f0deb47f3a3411fe6e7ede1b0d86ad4216c75041e1a2020f009f"),
        ),
        (
            1921835,
            decode_to_u32_array("0ef8aaa707662dc591558890d6e98fe25070392b342f447532cc4325547ad1a8"),
        ),
    ];

    pub const NIGHTLY_INITIAL_BATCH_PROOF_METHOD_IDS: &[(u64, [u32; 8])] = {
        match option_env!("BATCH_PROOF_METHOD_ID") {
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
                (200, citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
            ],
        }
    };

    pub const TEST_NETWORK_WITH_FORKS_INITIAL_BATCH_PROOF_METHOD_IDS: &[(u64, [u32; 8])] = {
        match option_env!("BATCH_PROOF_METHOD_ID") {
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
                (200, citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
            ],
        }
    };

    pub const MAINNET_BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"030000000000000000000000000000000000000000000000000000000000000000",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("PROVER_DA_PUB_KEY must be valid 33-byte hex string"),
    };

    pub const TESTNET_BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"0357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a42",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("PROVER_DA_PUB_KEY must be valid 33-byte hex string"),
    };

    pub const DEVNET_BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
        b"03fc6fb2ef68368009c895d2d4351dcca4109ec2f5f327291a0553570ce769f5e5",
    ) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("PROVER_DA_PUB_KEY must be valid 33-byte hex string"),
    };

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

    pub const TEST_NETWORK_WITH_FORKS_BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = {
        let hex_pub_key = match option_env!("PROVER_DA_PUB_KEY") {
            Some(hex_pub_key) => hex_pub_key,
            None => "03eedab888e45f3bdc3ec9918c491c11e5cf7af0a91f38b97fbc1e135ae4056601",
        };

        match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
            Ok(pub_key) => pub_key,
            Err(_) => panic!("PROVER_DA_PUB_KEY must be valid 33-byte hex string"),
        }
    };

    pub const MAINNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] =
        match const_hex::const_decode_to_array(
            b"000000000000000000000000000000000000000000000000000000000000000000",
        ) {
            Ok(pub_key) => pub_key,
            Err(_) => {
                panic!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY must be valid 33-byte hex string")
            }
        };

    pub const TESTNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] =
        match const_hex::const_decode_to_array(
            b"03796a3a8a86ff1cc37437585f0450f6059c397c01bce06bfbaaa36242f7ebfc02",
        ) {
            Ok(pub_key) => pub_key,
            Err(_) => {
                panic!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY must be valid 33-byte hex string")
            }
        };
    pub const DEVNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] =
        match const_hex::const_decode_to_array(
            b"0388e988066db18e19750fa92aa0fbf9c85104be2b5b507ce0aa7f30f3fe24b1ac",
        ) {
            Ok(pub_key) => pub_key,
            Err(_) => {
                panic!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY must be valid 33-byte hex string")
            }
        };

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

#[cfg(feature = "native")]
pub trait InitialValueProvider<Das: DaSpec> {
    fn get_l2_genesis_root(&self) -> [u8; 32];

    fn initial_batch_proof_method_ids(&self) -> Vec<(u64, [u32; 8])>;

    fn batch_prover_da_public_key(&self) -> [u8; 33];

    fn method_id_upgrade_authority_da_public_key(&self) -> [u8; 33];
}

#[cfg(feature = "native")]
impl InitialValueProvider<MockDaSpec> for Network {
    fn get_l2_genesis_root(&self) -> [u8; 32] {
        assert_eq!(self, &Network::Nightly, "Only nightly allowed on mock da!");
        mockda::GENESIS_ROOT
    }

    fn initial_batch_proof_method_ids(&self) -> Vec<(u64, [u32; 8])> {
        assert_eq!(self, &Network::Nightly, "Only nightly allowed on mock da!");
        mockda::INITIAL_BATCH_PROOF_METHOD_IDS.to_vec()
    }

    fn batch_prover_da_public_key(&self) -> [u8; 33] {
        assert_eq!(self, &Network::Nightly, "Only nightly allowed on mock da!");
        mockda::BATCH_PROVER_DA_PUBLIC_KEY
    }

    fn method_id_upgrade_authority_da_public_key(&self) -> [u8; 33] {
        assert_eq!(self, &Network::Nightly, "Only nightly allowed on mock da!");
        mockda::METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY
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

    fn initial_batch_proof_method_ids(&self) -> Vec<(u64, [u32; 8])> {
        match self {
            Network::Mainnet => bitcoinda::MAINNET_INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            Network::Testnet => bitcoinda::TESTNET_INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            Network::Devnet => bitcoinda::DEVNET_INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            Network::Nightly => bitcoinda::NIGHTLY_INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            Network::TestNetworkWithForks => {
                bitcoinda::TEST_NETWORK_WITH_FORKS_INITIAL_BATCH_PROOF_METHOD_IDS.to_vec()
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
}
