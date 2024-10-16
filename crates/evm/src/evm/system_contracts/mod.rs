use alloy_primitives::{address, Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall};

// BitcoinLightClient wrapper.
sol! {
    #[sol(abi)]
    #[allow(missing_docs)]
    BitcoinLightClientContract,
    "./src/evm/system_contracts/out/BitcoinLightClient.sol/BitcoinLightClient.json"
}

/// BitcoinLightClient wrapper.
pub struct BitcoinLightClient {}

impl BitcoinLightClient {
    /// Return the address of the BitcoinLightClient contract.
    pub fn address() -> Address {
        address!("3100000000000000000000000000000000000001")
    }

    pub(crate) fn init(block_number: u64) -> Bytes {
        let block_number = U256::from(block_number);

        let mut func_selector = Vec::with_capacity(4 + 32);
        func_selector.extend(BitcoinLightClientContract::initializeBlockNumberCall::SELECTOR);
        func_selector.extend_from_slice(&block_number.to_be_bytes::<32>());
        func_selector.into()
    }

    pub(crate) fn set_block_info(block_hash: [u8; 32], txs_commitments: [u8; 32]) -> Bytes {
        let mut func_selector = Vec::with_capacity(4 + 32 + 32);
        func_selector.extend(BitcoinLightClientContract::setBlockInfoCall::SELECTOR);
        func_selector.extend_from_slice(&block_hash);
        func_selector.extend_from_slice(&txs_commitments);
        func_selector.into()
    }

    /// Return input data to query the block hash by block number mapping
    pub fn get_block_hash(block_number: u64) -> Bytes {
        BitcoinLightClientContract::getBlockHashCall {
            _blockNumber: U256::from(block_number),
        }
        .abi_encode()
        .into()
    }

    /// Return input data to get the system caller
    pub fn get_system_caller() -> Bytes {
        BitcoinLightClientContract::SYSTEM_CALLERCall {}
            .abi_encode()
            .into()
    }

    #[cfg(all(test, feature = "native"))]
    pub(crate) fn get_witness_root_by_number(block_number: u64) -> Bytes {
        BitcoinLightClientContract::getWitnessRootByNumberCall {
            _blockNumber: U256::from(block_number),
        }
        .abi_encode()
        .into()
    }
}

// Bridge wrapper.
sol! {
    #[sol(abi)]
    #[allow(missing_docs)]
    BridgeContract,
    "./src/evm/system_contracts/out/Bridge.sol/Bridge.json"
}

/// Bridge wrapper.
pub struct BridgeWrapper {}

impl BridgeWrapper {
    /// Return the address of the Bridge contract.
    pub fn address() -> Address {
        address!("3100000000000000000000000000000000000002")
    }

    pub(crate) fn initialize() -> Bytes {
        // Hardcoded until better times.

        // This is equal to:
        //
        // BridgeContract::initializeCall {
        //     _scriptPrefix: hex!("4a209fb3a961d8b1f4ec1caa220c6a50b815febc0b689ddf0b9ddfbf99cb74479e41ac00630663697472656114").into(),
        //     _scriptSuffix: hex!("08000000003b9aca0068").into(),
        //     _depositAmount: U256::from(10 ether),
        // }
        // .abi_encode()

        // Swap with the below value if running Clementine E2E tests
        // let params = vec![
        //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //     0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //     0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //     0, 0, 138, 199, 35, 4, 137, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 74, 32, 124, 72, 3, 66, 25, 86, 219,
        //     83, 238, 210, 158, 228, 91, 221, 190, 96, 209, 110, 102, 86, 15, 145, 138, 148, 39, 14,
        //     165, 39, 43, 43, 78, 144, 172, 0, 99, 6, 99, 105, 116, 114, 101, 97, 20, 0, 0, 0, 0, 0,
        //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 8, 0, 0, 0, 0, 59, 154, 202, 0,
        //     104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        // ];

        let params = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 138, 199, 35, 4, 137, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 74, 32, 159, 179, 169, 97, 216, 177,
            244, 236, 28, 170, 34, 12, 106, 80, 184, 21, 254, 188, 11, 104, 157, 223, 11, 157, 223,
            191, 153, 203, 116, 71, 158, 65, 172, 0, 99, 6, 99, 105, 116, 114, 101, 97, 20, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 8, 0, 0, 0, 0, 59, 154,
            202, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let mut func_selector = Vec::with_capacity(4 + params.len());
        func_selector.extend(BridgeContract::initializeCall::SELECTOR);
        func_selector.extend(params);
        func_selector.into()
    }

    /// Return data to deposit
    pub fn deposit(params: Vec<u8>) -> Bytes {
        // Params can be read by `BridgeContract::depositCall::abi_decode_raw(&params, true)`
        let mut func_selector = Vec::with_capacity(4 + params.len());
        func_selector.extend(BridgeContract::depositCall::SELECTOR);
        func_selector.extend(params);
        func_selector.into()
    }
}

sol! {
    #[sol(abi)]
    #[allow(missing_docs)]
    ProxyAdminContract,
    "./src/evm/system_contracts/out/ProxyAdmin.sol/ProxyAdmin.json"
}

/// ProxyAdmin wrapper.
pub struct ProxyAdmin {}

impl ProxyAdmin {
    /// Return the address of the ProxyAdmin contract.
    pub fn address() -> Address {
        address!("31ffffffffffffffffffffffffffffffffffffff")
    }

    /// Return data to upgrade the contract.
    pub fn upgrade(proxy: Address, new_contract: Address) -> Bytes {
        ProxyAdminContract::upgradeCall {
            proxy,
            implementation: new_contract,
        }
        .abi_encode()
        .into()
    }

    /// Return data to transfer ownership.
    pub fn transfer_ownership(new_owner: Address) -> Bytes {
        ProxyAdminContract::transferOwnershipCall {
            newOwner: new_owner,
        }
        .abi_encode()
        .into()
    }

    /// Return data to query the owner.
    pub fn owner() -> Bytes {
        ProxyAdminContract::ownerCall {}.abi_encode().into()
    }
}
