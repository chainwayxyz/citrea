use alloy_primitives::{address, Address, U256 as Alloy256};
use alloy_sol_types::{sol, SolValue};
use ethers_contract::BaseContract;
use ethers_core::abi::Abi;
use ethers_core::types::Bytes;

fn make_contract_from_abi(abi_json: &str) -> BaseContract {
    let j: serde_json::Value = serde_json::from_str(abi_json).unwrap();
    let abi = &j.as_object().unwrap()["abi"];
    let abi: Abi = serde_json::from_value(abi.to_owned()).unwrap();
    BaseContract::from(abi)
}

/// L1BlockHashList wrapper.
pub struct L1BlockHashList {
    base_contract: BaseContract,
}

impl Default for L1BlockHashList {
    fn default() -> Self {
        let base_contract = make_contract_from_abi(include_str!(
            "./out/L1BlockHashList.sol/L1BlockHashList.json"
        ));
        Self { base_contract }
    }
}

impl L1BlockHashList {
    pub(crate) fn address() -> Address {
        address!("3100000000000000000000000000000000000001")
    }

    pub(crate) fn init(&self, block_number: u64) -> Bytes {
        let args = ethereum_types::U256::from(block_number);
        self.base_contract
            .encode("initializeBlockNumber", args)
            .expect("ABI for system contract should be correct")
    }

    pub(crate) fn set_block_info(&self, block_hash: [u8; 32], txs_commitments: [u8; 32]) -> Bytes {
        let args = (block_hash, txs_commitments);
        self.base_contract
            .encode("setBlockInfo", args)
            .expect("ABI for system contract should be correct")
    }

    /// Return input data to query the block hash by block number mapping
    pub fn get_block_hash(&self, block_number: u64) -> Bytes {
        let args = ethereum_types::U256::from(block_number);
        self.base_contract
            .encode("getBlockHash", args)
            .expect("ABI for system contract should be correct")
    }

    #[allow(dead_code)]
    pub(crate) fn get_witness_root_by_number(&self, block_number: u64) -> Bytes {
        let args = ethereum_types::U256::from(block_number);
        self.base_contract
            .encode("getWitnessRootByNumber", args)
            .expect("ABI for system contract should be correct")
    }
}

/// Bridge wrapper.
pub struct Bridge {
    base_contract: BaseContract,
}

impl Default for Bridge {
    fn default() -> Self {
        let base_contract = make_contract_from_abi(include_str!("./out/Bridge.sol/Bridge.json"));
        Self { base_contract }
    }
}

impl Bridge {
    pub(crate) fn address() -> Address {
        address!("3100000000000000000000000000000000000002")
    }

    pub(crate) fn initialize(
        &self,
        levels: u32,
        deposit_script: Bytes,
        script_suffix: Bytes,
        required_sigs_count: u64,
    ) -> Bytes {
        let args = (
            levels,
            deposit_script,
            script_suffix,
            ethereum_types::U256::from(required_sigs_count),
        );
        self.base_contract
            .encode("initialize", args)
            .expect("ABI for system contract should be correct")
    }

    pub(crate) fn deposit(
        &self,
        version: [u8; 4],
        flag: [u8; 2],
        vin: Bytes,
        vout: Bytes,
        witness: Bytes,
        locktime: [u8; 4],
        intermediate_nodes: Bytes,
        block_height: u64,
        index: u64,
    ) -> Bytes {
        sol! {
            struct DepositParams {
                bytes4 version;
                bytes2 flag;
                bytes vin;
                bytes vout;
                bytes witness;
                bytes4 locktime;
                bytes intermediate_nodes;
                uint256 block_height;
                uint256 index;
            }
        }

        let args = DepositParams {
            version: alloy_primitives::FixedBytes(version),
            flag: alloy_primitives::FixedBytes(flag),
            vin: vin.to_vec(),
            vout: vout.to_vec(),
            witness: witness.to_vec(),
            locktime: alloy_primitives::FixedBytes(locktime),
            intermediate_nodes: intermediate_nodes.to_vec(),
            block_height: Alloy256::from(block_height),
            index: Alloy256::from(index),
        };

        DepositParams::abi_encode_sequence(&args).into()
    }
}
