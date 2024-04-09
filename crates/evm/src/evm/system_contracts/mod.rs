use alloy_primitives::{address, Address};
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
    pub(crate) fn get_merkle_root_by_number(&self, block_number: u64) -> Bytes {
        let args = ethereum_types::U256::from(block_number);
        self.base_contract
            .encode("getMerkleRootByNumber", args)
            .expect("ABI for system contract should be correct")
    }
}
