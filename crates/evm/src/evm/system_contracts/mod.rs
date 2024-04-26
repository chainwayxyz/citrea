use alloy_primitives::{address, Address, Bytes, U256};

/// BitcoinLightClient wrapper.
pub struct BitcoinLightClient {}

impl BitcoinLightClient {
    pub(crate) fn address() -> Address {
        address!("3100000000000000000000000000000000000001")
    }

    pub(crate) fn init(block_number: u64) -> Bytes {
        let mut func_selector: Vec<u8> = vec![0x1f, 0x57, 0x83, 0x33]; // initializeBlockNumber(u256) 1f578333

        let block_number = U256::from(block_number);
        func_selector.extend_from_slice(&block_number.to_be_bytes::<32>());

        Bytes::from(func_selector)
    }

    pub(crate) fn set_block_info(block_hash: [u8; 32], txs_commitments: [u8; 32]) -> Bytes {
        let mut func_selector = vec![0x0e, 0x27, 0xbc, 0x11]; // setBlockInfo(bytes32, bytes32) 0e27bc11

        func_selector.extend_from_slice(&block_hash);
        func_selector.extend_from_slice(&txs_commitments);

        Bytes::from(func_selector)
    }

    /// Return input data to query the block hash by block number mapping
    pub fn get_block_hash(block_number: u64) -> Bytes {
        let mut func_selector: Vec<u8> = vec![0xee, 0x82, 0xac, 0x5e]; // getBlockHash(uint256) ee82ac5e

        let block_number = U256::from(block_number);
        println!("block_number: {:?}", block_number);
        func_selector.extend_from_slice(&block_number.to_be_bytes::<32>());

        Bytes::from(func_selector)
    }

    #[allow(dead_code)]
    pub(crate) fn get_witness_root_by_number(block_number: u64) -> Bytes {
        let mut func_selector: Vec<u8> = vec![0x61, 0xb2, 0x07, 0xe2]; // getWitnessRootByNumber(uint256) 61b207e2

        let block_number = U256::from(block_number);
        func_selector.extend_from_slice(&block_number.to_be_bytes::<32>());

        Bytes::from(func_selector)
    }
}
