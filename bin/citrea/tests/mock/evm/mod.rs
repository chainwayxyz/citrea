use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use alloy::consensus::constants::KECCAK_EMPTY;
// use citrea::initialize_logging;
use alloy_primitives::{Address, Bytes, U256};
use alloy_rpc_types::EIP1186AccountProofResponse;
use citrea_common::SequencerConfig;
use citrea_evm::smart_contracts::{LogsContract, SimpleStorageContract, TestContract};
use citrea_evm::system_contracts::BitcoinLightClient;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{BlockId, BlockNumberOrTag};
use sha2::Digest;
use sov_rollup_interface::{Network, CITREA_VERSION};
use sov_state::KeyHash;
use tokio::time::sleep;

// use sov_demo_rollup::initialize_logging;
use crate::common::client::TestClient;
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::common::{
    make_test_client, TEST_DATA_GENESIS_PATH, TEST_SEND_NO_COMMITMENT_MIN_L2_BLOCKS_PER_COMMITMENT,
};

mod archival_state;
mod fee;
mod gas_price;
mod subscription;
mod tracing;

#[tokio::test(flavor = "multi_thread")]
async fn web3_rpc_tests() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequener_config = SequencerConfig::default();
    let rollup_task = tokio::spawn(async {
        start_rollup(
            port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequener_config),
            None,
            false,
        )
        .await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();

    let test_client = make_test_client(port).await?;

    let arch = std::env::consts::ARCH;

    assert_eq!(
        test_client.web3_client_version().await,
        format!(
            "citrea/{}/{}/rust-{}",
            CITREA_VERSION,
            arch,
            rustc_version_runtime::version()
        )
    );
    assert_eq!(
        test_client
            .web3_sha3("0x68656c6c6f20776f726c64".to_string())
            .await,
        "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad".to_string()
    );

    rollup_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn evm_tx_tests() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig {
        min_l2_blocks_per_commitment: TEST_SEND_NO_COMMITMENT_MIN_L2_BLOCKS_PER_COMMITMENT,
        ..Default::default()
    };
    let rollup_task = tokio::spawn(async {
        start_rollup(
            port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
            None,
            false,
        )
        .await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();
    send_tx_test_to_eth(port).await.unwrap();
    rollup_task.abort();
    Ok(())
}

async fn send_tx_test_to_eth(rpc_address: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let test_client = init_test_rollup(rpc_address).await;
    execute(&test_client).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_get_logs() -> Result<(), anyhow::Error> {
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig::default();

    let rollup_task = tokio::spawn(async {
        start_rollup(
            port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
            None,
            false,
        )
        .await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();

    let test_client = init_test_rollup(port).await;

    test_getlogs(&test_client).await.unwrap();

    rollup_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_genesis_contract_call() -> Result<(), Box<dyn std::error::Error>> {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig {
        min_l2_blocks_per_commitment: 123456,
        ..Default::default()
    };
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../../resources/genesis/mock-dockerized/"),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
            None,
            false,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await?;
    // call the contract with address 0x3100000000000000000000000000000000000001
    let contract_address = Address::from_str("0x3100000000000000000000000000000000000001").unwrap();

    let code = seq_test_client
        .eth_get_code(contract_address, None)
        .await
        .unwrap();

    let expected_code = "60806040523661001357610011610017565b005b6100115b61001f610168565b6001600160a01b0316330361015e5760606001600160e01b03195f35166364d3180d60e11b81016100595761005261019a565b9150610156565b63587086bd60e11b6001600160e01b0319821601610079576100526101ed565b63070d7c6960e41b6001600160e01b031982160161009957610052610231565b621eb96f60e61b6001600160e01b03198216016100b857610052610261565b63a39f25e560e01b6001600160e01b03198216016100d8576100526102a0565b60405162461bcd60e51b815260206004820152604260248201527f5472616e73706172656e745570677261646561626c6550726f78793a2061646d60448201527f696e2063616e6e6f742066616c6c6261636b20746f2070726f78792074617267606482015261195d60f21b608482015260a4015b60405180910390fd5b815160208301f35b6101666102b3565b565b5f7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b546001600160a01b0316919050565b60606101a46102c3565b5f6101b23660048184610668565b8101906101bf91906106aa565b90506101da8160405180602001604052805f8152505f6102cd565b505060408051602081019091525f815290565b60605f806101fe3660048184610668565b81019061020b91906106d7565b9150915061021b828260016102cd565b60405180602001604052805f8152509250505090565b606061023b6102c3565b5f6102493660048184610668565b81019061025691906106aa565b90506101da816102f8565b606061026b6102c3565b5f610274610168565b604080516001600160a01b03831660208201529192500160405160208183030381529060405291505090565b60606102aa6102c3565b5f61027461034f565b6101666102be61034f565b61035d565b3415610166575f5ffd5b6102d68361037b565b5f825111806102e25750805b156102f3576102f183836103ba565b505b505050565b7f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f610321610168565b604080516001600160a01b03928316815291841660208301520160405180910390a161034c816103e6565b50565b5f61035861048f565b905090565b365f5f375f5f365f845af43d5f5f3e808015610377573d5ff35b3d5ffd5b610384816104b6565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b905f90a250565b60606103df83836040518060600160405280602781526020016107e76027913961054a565b9392505050565b6001600160a01b03811661044b5760405162461bcd60e51b815260206004820152602660248201527f455243313936373a206e65772061646d696e20697320746865207a65726f206160448201526564647265737360d01b606482015260840161014d565b807fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b80546001600160a01b0319166001600160a01b039290921691909117905550565b5f7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61018b565b6001600160a01b0381163b6105235760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b606482015260840161014d565b807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61046e565b60605f5f856001600160a01b031685604051610566919061079b565b5f60405180830381855af49150503d805f811461059e576040519150601f19603f3d011682016040523d82523d5f602084013e6105a3565b606091505b50915091506105b4868383876105be565b9695505050505050565b6060831561062c5782515f03610625576001600160a01b0385163b6106255760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161014d565b5081610636565b610636838361063e565b949350505050565b81511561064e5781518083602001fd5b8060405162461bcd60e51b815260040161014d91906107b1565b5f5f85851115610676575f5ffd5b83861115610682575f5ffd5b5050820193919092039150565b80356001600160a01b03811681146106a5575f5ffd5b919050565b5f602082840312156106ba575f5ffd5b6103df8261068f565b634e487b7160e01b5f52604160045260245ffd5b5f5f604083850312156106e8575f5ffd5b6106f18361068f565b9150602083013567ffffffffffffffff81111561070c575f5ffd5b8301601f8101851361071c575f5ffd5b803567ffffffffffffffff811115610736576107366106c3565b604051601f8201601f19908116603f0116810167ffffffffffffffff81118282101715610765576107656106c3565b60405281815282820160200187101561077c575f5ffd5b816020840160208301375f602083830101528093505050509250929050565b5f82518060208501845e5f920191825250919050565b602081525f82518060208401528060208501604085015e5f604082850101526040601f19601f8301168401019150509291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564";
    assert_eq!(code.to_vec(), hex::decode(expected_code).unwrap());

    let res: String = seq_test_client
        .contract_call(
            contract_address,
            BitcoinLightClient::get_system_caller().into(),
            None,
        )
        .await
        .unwrap();
    let expected_res = "0x000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead";
    assert_eq!(res, expected_res);

    let storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            U256::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
                .unwrap(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        storage_value,
        U256::from_str("0x0000000000000000000000003200000000000000000000000000000000000001")
            .unwrap()
    );

    seq_task.abort();
    Ok(())
}

fn check_proof(acc_proof: &EIP1186AccountProofResponse, account_address: Address) {
    // println!("root: {:?}", acc_proof.storage_hash);
    // println!("proof: {:?}", acc_proof);

    // Verify proof:
    let expected_root_hash = acc_proof.storage_hash.0.into();

    // construct account key/values to be verified
    dbg!("verify proof acc");
    let account_key = [b"E/i/", account_address.as_slice()].concat();
    let account_hash = KeyHash::with::<sha2::Sha256>(account_key.clone());

    if acc_proof.account_proof.len() == 2 {
        // Neither account index nor account exist
        assert_eq!(acc_proof.account_proof[1], Bytes::from("n"));

        let acc_storage_proof: jmt::proof::SparseMerkleProof<sha2::Sha256> =
            borsh::from_slice(&acc_proof.account_proof[0]).unwrap();

        acc_storage_proof
            .verify(expected_root_hash, account_hash, None::<Vec<u8>>)
            .expect("Account proof must be valid");
    } else {
        // index_proof, index_bytes, account_proof, account_exists
        assert_eq!(acc_proof.account_proof.len(), 4);

        let proved_index_value = acc_proof.account_proof[1].to_vec();
        let account_idx = usize::from_le_bytes(
            proved_index_value
                .clone()
                .try_into()
                .expect("Must be exactly 8 bytes"),
        );

        let acc_index_proof: jmt::proof::SparseMerkleProof<sha2::Sha256> =
            borsh::from_slice(&acc_proof.account_proof[0]).unwrap();

        acc_index_proof
            .verify(expected_root_hash, account_hash, Some(proved_index_value))
            .expect("Account proof index must be valid");

        let proved_account = if acc_proof.account_proof[3] == Bytes::from("y") {
            dbg!("acc exists");
            // Account exists and it's serialized form is:
            let code_hash_bytes = if acc_proof.code_hash != KECCAK_EMPTY {
                // 1 for Some
                [&[1], acc_proof.code_hash.0.as_slice()].concat()
            } else {
                // 0 for None
                vec![0]
            };
            let bytes = [
                acc_proof.balance.as_le_slice(),
                &acc_proof.nonce.to_le_bytes(),
                &code_hash_bytes,
            ]
            .concat();
            Some(bytes)
        } else {
            // Account does not exist
            dbg!("acc does not exist");
            None
        };

        let index_key = [b"E/a/", account_idx.to_le_bytes().as_slice()].concat();
        let index_hash = KeyHash::with::<sha2::Sha256>(index_key.clone());

        let acc_proof: jmt::proof::SparseMerkleProof<sha2::Sha256> =
            borsh::from_slice(&acc_proof.account_proof[2]).unwrap();

        acc_proof
            .verify(expected_root_hash, index_hash, proved_account)
            .expect("Account proof must be valid");
    }

    for storage_proof in &acc_proof.storage_proof {
        let kaddr = {
            let mut hasher: sha2::Sha256 =
                sha2::Digest::new_with_prefix(account_address.as_slice());
            hasher.update(storage_proof.key.0.as_slice());
            let arr = hasher.finalize();
            U256::from_le_slice(&arr)
        };
        let storage_key = [b"E/s/".as_slice(), kaddr.as_le_slice()].concat();
        let key_hash = KeyHash::with::<sha2::Sha256>(storage_key.clone());

        let proved_value = if storage_proof.proof[1] == Bytes::from("y") {
            dbg!("storage exists");
            // Storage value exists and it's serialized form is:
            let bytes = storage_proof.value.as_le_bytes().to_vec();
            Some(bytes)
        } else {
            // Storage value does not exist
            dbg!("storage does not exist");
            None
        };

        let storage_proof: jmt::proof::SparseMerkleProof<sha2::Sha256> =
            borsh::from_slice(&storage_proof.proof[0]).unwrap();

        storage_proof
            .verify(expected_root_hash, key_hash, proved_value)
            .expect("Account storage proof must be valid");
    }
}

async fn test_eth_get_proof_on(network: Network) -> Result<(), Box<dyn std::error::Error>> {
    // citrea::initialize_logging(::tracing::Level::INFO);
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig {
        min_l2_blocks_per_commitment: 123456,
        ..Default::default()
    };
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../../resources/genesis/mock-dockerized/"),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
            Some(network),
            false,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await?;
    // call the contract with address 0x3100000000000000000000000000000000000001
    let contract_address = Address::from_str("0x3100000000000000000000000000000000000001").unwrap();

    let code = seq_test_client
        .eth_get_code(contract_address, None)
        .await
        .unwrap();

    let expected_code = "60806040523661001357610011610017565b005b6100115b61001f610168565b6001600160a01b0316330361015e5760606001600160e01b03195f35166364d3180d60e11b81016100595761005261019a565b9150610156565b63587086bd60e11b6001600160e01b0319821601610079576100526101ed565b63070d7c6960e41b6001600160e01b031982160161009957610052610231565b621eb96f60e61b6001600160e01b03198216016100b857610052610261565b63a39f25e560e01b6001600160e01b03198216016100d8576100526102a0565b60405162461bcd60e51b815260206004820152604260248201527f5472616e73706172656e745570677261646561626c6550726f78793a2061646d60448201527f696e2063616e6e6f742066616c6c6261636b20746f2070726f78792074617267606482015261195d60f21b608482015260a4015b60405180910390fd5b815160208301f35b6101666102b3565b565b5f7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b546001600160a01b0316919050565b60606101a46102c3565b5f6101b23660048184610668565b8101906101bf91906106aa565b90506101da8160405180602001604052805f8152505f6102cd565b505060408051602081019091525f815290565b60605f806101fe3660048184610668565b81019061020b91906106d7565b9150915061021b828260016102cd565b60405180602001604052805f8152509250505090565b606061023b6102c3565b5f6102493660048184610668565b81019061025691906106aa565b90506101da816102f8565b606061026b6102c3565b5f610274610168565b604080516001600160a01b03831660208201529192500160405160208183030381529060405291505090565b60606102aa6102c3565b5f61027461034f565b6101666102be61034f565b61035d565b3415610166575f5ffd5b6102d68361037b565b5f825111806102e25750805b156102f3576102f183836103ba565b505b505050565b7f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f610321610168565b604080516001600160a01b03928316815291841660208301520160405180910390a161034c816103e6565b50565b5f61035861048f565b905090565b365f5f375f5f365f845af43d5f5f3e808015610377573d5ff35b3d5ffd5b610384816104b6565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b905f90a250565b60606103df83836040518060600160405280602781526020016107e76027913961054a565b9392505050565b6001600160a01b03811661044b5760405162461bcd60e51b815260206004820152602660248201527f455243313936373a206e65772061646d696e20697320746865207a65726f206160448201526564647265737360d01b606482015260840161014d565b807fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b80546001600160a01b0319166001600160a01b039290921691909117905550565b5f7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61018b565b6001600160a01b0381163b6105235760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b606482015260840161014d565b807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61046e565b60605f5f856001600160a01b031685604051610566919061079b565b5f60405180830381855af49150503d805f811461059e576040519150601f19603f3d011682016040523d82523d5f602084013e6105a3565b606091505b50915091506105b4868383876105be565b9695505050505050565b6060831561062c5782515f03610625576001600160a01b0385163b6106255760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161014d565b5081610636565b610636838361063e565b949350505050565b81511561064e5781518083602001fd5b8060405162461bcd60e51b815260040161014d91906107b1565b5f5f85851115610676575f5ffd5b83861115610682575f5ffd5b5050820193919092039150565b80356001600160a01b03811681146106a5575f5ffd5b919050565b5f602082840312156106ba575f5ffd5b6103df8261068f565b634e487b7160e01b5f52604160045260245ffd5b5f5f604083850312156106e8575f5ffd5b6106f18361068f565b9150602083013567ffffffffffffffff81111561070c575f5ffd5b8301601f8101851361071c575f5ffd5b803567ffffffffffffffff811115610736576107366106c3565b604051601f8201601f19908116603f0116810167ffffffffffffffff81118282101715610765576107656106c3565b60405281815282820160200187101561077c575f5ffd5b816020840160208301375f602083830101528093505050509250929050565b5f82518060208501845e5f920191825250919050565b602081525f82518060208401528060208501604085015e5f604082850101526040601f19601f8301168401019150509291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564";
    assert_eq!(code.to_vec(), hex::decode(expected_code).unwrap());

    let res: String = seq_test_client
        .contract_call(
            contract_address,
            BitcoinLightClient::get_system_caller().into(),
            None,
        )
        .await
        .unwrap();
    let expected_res = "0x000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead";
    assert_eq!(res, expected_res);

    let contract_field =
        U256::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
            .unwrap();

    let storage_value = seq_test_client
        .eth_get_storage_at(contract_address, contract_field, None)
        .await
        .unwrap();
    assert_eq!(
        storage_value,
        U256::from_str("0x0000000000000000000000003200000000000000000000000000000000000001")
            .unwrap()
    );

    let non_existing_field = U256::from(42);
    let non_existing_value = seq_test_client
        .eth_get_storage_at(contract_address, non_existing_field, None)
        .await
        .unwrap();
    assert_eq!(non_existing_value, U256::ZERO);

    let acc_proof_latest = seq_test_client
        .eth_get_proof(
            contract_address,
            vec![contract_field, non_existing_field],
            None,
        )
        .await
        .unwrap();

    {
        check_proof(&acc_proof_latest, contract_address);
        for storage_proof in &acc_proof_latest.storage_proof {
            if U256::from_le_slice(storage_proof.key.0.as_slice()) == contract_field {
                // A sanity check to verify we deal with the same value.
                // This check is not actually required, it's for test purposes only
                assert_eq!(storage_proof.value, storage_value);
            }
        }
    }

    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_secs(1)).await;

    let block_num = seq_test_client.eth_block_number().await;

    let acc_proof_1 = seq_test_client
        .eth_get_proof(
            contract_address,
            vec![contract_field, non_existing_field],
            Some(BlockNumberOrTag::Number(block_num)),
        )
        .await
        .unwrap();

    let acc_proof_2 = seq_test_client
        .eth_get_proof(
            contract_address,
            vec![contract_field, non_existing_field],
            Some(BlockNumberOrTag::Number(block_num - 1)),
        )
        .await
        .unwrap();

    {
        check_proof(&acc_proof_1, contract_address);
        for storage_proof in &acc_proof_1.storage_proof {
            if U256::from_le_slice(storage_proof.key.0.as_slice()) == contract_field {
                // A sanity check to verify we deal with the same value.
                // This check is not actually required, it's for test purposes only
                assert_eq!(storage_proof.value, storage_value);
            }
        }
    }

    {
        // Assert historic proof is not the same as the first one queried
        //  because storage root is different -> all proofs are different too.
        assert_ne!(acc_proof_1, acc_proof_2);
        check_proof(&acc_proof_2, contract_address);
        for storage_proof in &acc_proof_2.storage_proof {
            if U256::from_le_slice(storage_proof.key.0.as_slice()) == contract_field {
                // A sanity check to verify we deal with the same value.
                // This check is not actually required, it's for test purposes only
                assert_eq!(storage_proof.value, storage_value);
            }
        }
    }

    {
        // Assert historic proof is the same as the first one queried.
        assert_eq!(acc_proof_latest, acc_proof_2);
    }

    seq_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_get_proof_devnet() -> Result<(), Box<dyn std::error::Error>> {
    test_eth_get_proof_on(Network::Devnet).await
}

#[allow(clippy::borrowed_box)]
async fn test_getlogs(client: &Box<TestClient>) -> Result<(), Box<dyn std::error::Error>> {
    let (contract_address, contract) = {
        let contract = LogsContract::default();
        let deploy_contract_req = client.deploy_contract(contract.byte_code(), None).await?;

        client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await?
            .contract_address
            .unwrap();

        (contract_address, contract)
    };

    let _pending_tx = client
        .contract_transaction(
            contract_address,
            contract.publish_event("hello".to_string()),
            None,
        )
        .await;
    client.send_publish_batch_request().await;
    wait_for_l2_block(client, 2, None).await;

    let empty_filter = serde_json::json!({});
    // supposed to get all the logs
    let logs = client.eth_get_logs(empty_filter).await;

    assert_eq!(logs.len(), 2);

    let one_topic_filter = serde_json::json!({
        "topics": [
            "0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7"
        ]
    });
    // supposed to get the first log only
    let logs = client.eth_get_logs(one_topic_filter).await;

    assert_eq!(logs.len(), 1);
    assert_eq!(
        hex::encode(logs[0].topics[0]).to_string(),
        "a9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7"
    );

    let sepolia_log_data = "\"0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000\"".to_string();
    let len = sepolia_log_data.len();
    assert_eq!(sepolia_log_data[1..len - 1], logs[0].data.to_string());

    // Deploy another contract
    let contract_address2 = {
        let deploy_contract_req = client.deploy_contract(contract.byte_code(), None).await?;
        client.send_publish_batch_request().await;
        wait_for_l2_block(client, 2, None).await;

        deploy_contract_req
            .get_receipt()
            .await?
            .contract_address
            .unwrap()
    };

    // call the second contract again
    let _pending_tx = client
        .contract_transaction(
            contract_address2,
            contract.publish_event("second contract".to_string()),
            None,
        )
        .await;
    client.send_publish_batch_request().await;
    wait_for_l2_block(client, 3, None).await;

    // make sure the two contracts have different addresses
    assert_ne!(contract_address, contract_address2);

    // without any range or blockhash default behaviour is checking the latest block
    let just_address_filter = serde_json::json!({
        "address": contract_address
    });

    let logs = client.eth_get_logs(just_address_filter).await;
    // supposed to get both the logs coming from the contract
    assert_eq!(logs.len(), 0);

    // now we need to get all the logs with the first contract address
    let address_and_range_filter = serde_json::json!({
        "address": contract_address,
        "fromBlock": "0x1",
        "toBlock": "0x4"
    });

    let logs = client.eth_get_logs(address_and_range_filter).await;
    assert_eq!(logs.len(), 2);
    // make sure the address is the old one and not the new one
    assert_eq!(logs[0].address, contract_address);
    assert_eq!(logs[1].address, contract_address);

    Ok(())
}

#[allow(clippy::borrowed_box)]
async fn execute(client: &Box<TestClient>) -> Result<(), Box<dyn std::error::Error>> {
    // Nonce should be 0 in genesis
    let nonce = client
        .eth_get_transaction_count(client.from_addr, None)
        .await
        .unwrap();
    assert_eq!(0, nonce);

    // Balance should be > 0 in genesis
    let balance = client
        .eth_get_balance(client.from_addr, None)
        .await
        .unwrap();
    assert!(balance > U256::from(0));

    let (contract_address, contract, runtime_code) = {
        let contract = SimpleStorageContract::default();

        let runtime_code = client
            .deploy_contract_call(contract.byte_code(), None)
            .await?;
        let deploy_contract_req = client.deploy_contract(contract.byte_code(), None).await?;
        client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await?
            .contract_address
            .unwrap();

        (contract_address, contract, runtime_code)
    };

    // Assert contract deployed correctly
    let code = client.eth_get_code(contract_address, None).await.unwrap();
    // code has natural following 0x00 bytes, so we need to trim it
    assert_eq!(code.to_vec()[..runtime_code.len()], runtime_code.to_vec());

    // Nonce should be 1 after the deploy
    let nonce = client
        .eth_get_transaction_count(client.from_addr, None)
        .await
        .unwrap();
    assert_eq!(1, nonce);

    // Check that the first block has published
    // It should have a single transaction, deploying the contract
    let first_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
        .await;
    assert_eq!(first_block.header.number, 1);
    assert_eq!(first_block.transactions.len(), 4);

    let set_arg = 923;
    let tx_hash = {
        let set_value_req = client
            .contract_transaction(contract_address, contract.set_call_data(set_arg), None)
            .await;
        client.send_publish_batch_request().await;
        set_value_req.get_receipt().await.unwrap().transaction_hash
    };
    // Now we have a second block
    let second_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(2)))
        .await;
    assert_eq!(second_block.header.number, 2);

    // Assert getTransactionByBlockHashAndIndex
    let tx_by_hash = client
        .eth_get_tx_by_block_hash_and_index(second_block.header.hash, U256::from(0))
        .await;
    assert_eq!(tx_by_hash.hash, tx_hash);

    // Assert getTransactionByBlockNumberAndIndex
    let tx_by_number = client
        .eth_get_tx_by_block_number_and_index(BlockNumberOrTag::Number(2), U256::from(0))
        .await;
    let tx_by_number_tag = client
        .eth_get_tx_by_block_number_and_index(BlockNumberOrTag::Latest, U256::from(0))
        .await;
    assert_eq!(tx_by_number.hash, tx_hash);
    assert_eq!(tx_by_number_tag.hash, tx_hash);

    let get_arg: U256 = client
        .contract_call(contract_address, contract.get_call_data(), None)
        .await?;

    assert_eq!(set_arg, get_arg.saturating_to::<u32>());

    // Assert storage slot is set
    let storage_slot = 0x0;
    let storage_value = client
        .eth_get_storage_at(contract_address, U256::from(storage_slot), None)
        .await
        .unwrap();
    assert_eq!(storage_value, U256::from(set_arg));

    // Check that the second block has published
    // None should return the latest block
    // It should have a single transaction, setting the value
    let latest_block = client.eth_get_block_by_number_with_detail(None).await;
    let block_transactions: Vec<_> = latest_block.transactions.hashes().clone().collect();
    assert_eq!(latest_block.header.number, 2);
    assert_eq!(block_transactions.len(), 1);
    assert_eq!(block_transactions[0], tx_hash);

    // This should just pass without error
    let _: Bytes = client
        .contract_call(contract_address, contract.set_call_data(set_arg), None)
        .await?;

    // This call should fail because function does not exist
    let failing_call: Result<Bytes, _> = client
        .contract_call(
            contract_address,
            contract.failing_function_call_data(),
            None,
        )
        .await;
    assert!(failing_call.is_err());

    // Create a blob with multiple transactions.
    client.sync_nonce().await; // sync nonce because of failed call
    let mut requests = Vec::default();
    for value in 150..153 {
        let set_value_req = client
            .contract_transaction(contract_address, contract.set_call_data(value), None)
            .await;
        requests.push(set_value_req);
    }

    client.send_publish_batch_request().await;
    client.send_publish_batch_request().await;
    for req in requests {
        req.get_receipt().await.unwrap();
    }

    {
        let get_arg: U256 = client
            .contract_call(contract_address, contract.get_call_data(), None)
            .await?;
        // should be one of three values sent in a single block. 150, 151, or 152
        assert!((150..=152).contains(&get_arg.saturating_to()));
    }

    {
        let value = 103;

        let tx_hash = {
            let set_value_req = client
                .contract_transaction(contract_address, contract.set_call_data(value), None)
                .await;

            client.send_publish_batch_request().await;
            set_value_req.get_receipt().await.unwrap().transaction_hash
        };

        let latest_block = client.eth_get_block_by_number(None).await;
        let block_transactions = latest_block.transactions.as_hashes().unwrap();
        assert_eq!(block_transactions.len(), 1);
        assert_eq!(block_transactions[0], tx_hash);

        let latest_block_receipts = client
            .eth_get_block_receipts(BlockId::Number(BlockNumberOrTag::Latest))
            .await;
        let latest_block_receipt_by_number = client
            .eth_get_block_receipts(BlockId::Number(BlockNumberOrTag::Number(
                latest_block.header.number,
            )))
            .await;
        assert_eq!(latest_block_receipts, latest_block_receipt_by_number);
        assert_eq!(latest_block_receipts.len(), 1);
        assert_eq!(latest_block_receipts[0].transaction_hash, tx_hash);
        let tx_receipt = client.eth_get_transaction_receipt(tx_hash).await.unwrap();
        assert_eq!(tx_receipt, latest_block_receipts[0]);

        let get_arg: U256 = client
            .contract_call(contract_address, contract.get_call_data(), None)
            .await?;

        assert_eq!(value, get_arg.saturating_to::<u32>());
    }

    let first_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(0)))
        .await;
    let second_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
        .await;

    // assert parent hash works correctly
    assert_eq!(
        first_block.header.hash, second_block.header.parent_hash,
        "Parent hash should be the hash of the previous block"
    );

    Ok(())
}

#[allow(clippy::borrowed_box)]
pub async fn init_test_rollup(rpc_address: SocketAddr) -> Box<TestClient> {
    let test_client = make_test_client(rpc_address).await.unwrap();

    let eth_chain_id = test_client.eth_chain_id().await;
    assert_eq!(5655, eth_chain_id);

    // No block exists yet
    let latest_block = test_client.eth_get_block_by_number(None).await;
    let earliest_block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Earliest))
        .await;

    assert_eq!(latest_block, earliest_block);
    assert_eq!(latest_block.header.number, 0);
    test_client
}
