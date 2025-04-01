#![allow(missing_docs)]
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

    pub(crate) fn set_block_info(
        block_hash: [u8; 32],
        txs_commitments: [u8; 32],
        coinbase_depth: u64,
    ) -> Bytes {
        let coinbase_depth = U256::from(coinbase_depth);

        let mut func_selector = Vec::with_capacity(4 + 32 + 32 + 32);
        func_selector.extend(BitcoinLightClientContract::setBlockInfoCall::SELECTOR);
        func_selector.extend_from_slice(&block_hash);
        func_selector.extend_from_slice(&txs_commitments);
        func_selector.extend_from_slice(&coinbase_depth.to_be_bytes::<32>());
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
    #[allow(missing_docs)]
    #[sol(abi)]
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

    pub(crate) fn initialize(params: &[u8]) -> Bytes {
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

sol!(
    #[sol(abi)]
    #[allow(missing_docs)]
    WCBTC9Contract,
    "./src/evm/system_contracts/out/WCBTC9.sol/WCBTC9.json"
);

/// WCBTC wrapper.
pub struct WCBTC {}

impl WCBTC {
    /// Return the address of the WCBTC contract.
    pub fn address() -> Address {
        address!("3100000000000000000000000000000000000006")
    }

    pub fn balance_of(account: Address) -> Bytes {
        WCBTC9Contract::balanceOfCall { _0: account }
            .abi_encode()
            .into()
    }

    pub fn deposit() -> Bytes {
        WCBTC9Contract::depositCall {}.abi_encode().into()
    }

    pub fn withdraw(amount: U256) -> Bytes {
        WCBTC9Contract::withdrawCall { wad: amount }
            .abi_encode()
            .into()
    }
}
