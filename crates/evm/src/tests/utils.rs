use std::collections::HashMap;
use std::path::Path;

use alloy_eips::eip1559::BaseFeeParams;
use lazy_static::lazy_static;
use reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT;
use reth_primitives::hex_literal::hex;
use reth_primitives::{address, Address, Bytes, TxKind, B256};
use revm::primitives::{KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::{Module, Spec, WorkingSet};
use sov_prover_storage_manager::{new_orphan_storage, SnapshotManager};
use sov_rollup_interface::spec::SpecId as SovSpecId;
use sov_state::{ProverStorage, Storage};
use sov_stf_runner::read_json_file;

use crate::smart_contracts::{LogsContract, SimpleStorageContract, TestContract};
use crate::tests::test_signer::TestSigner;
use crate::{AccountData, Evm, EvmConfig, RlpEvmTransaction, PRIORITY_FEE_VAULT};

type C = DefaultContext;

lazy_static! {
    pub(crate) static ref GENESIS_HASH: B256 = B256::from(hex!(
        "600287474db03ec020caf020ad58fe9c7918bd9b078ddfdba31642daae8bdffe"
    ));
    pub(crate) static ref GENESIS_STATE_ROOT: B256 = B256::from(hex!(
        "6945eecef532f6de29cc417e3b9c2a948ab9b0af8c167392c3955a090f1cbb16"
    ));
}

pub(crate) fn get_evm_with_storage(
    config: &EvmConfig,
) -> (
    Evm<C>,
    WorkingSet<ProverStorage<SnapshotManager>>,
    ProverStorage<SnapshotManager>,
) {
    let tmpdir = tempfile::tempdir().unwrap();
    let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
    let mut working_set = WorkingSet::new(prover_storage.clone());
    let evm = Evm::<C>::default();
    evm.genesis(config, &mut working_set);

    let mut genesis_state_root = [0u8; 32];
    genesis_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());

    evm.finalize_hook(
        &genesis_state_root.into(),
        &mut working_set.accessory_state(),
    );
    (evm, working_set, prover_storage)
}
pub(crate) fn get_evm(config: &EvmConfig) -> (Evm<C>, WorkingSet<<C as Spec>::Storage>) {
    let tmpdir = tempfile::tempdir().unwrap();
    let storage = new_orphan_storage(tmpdir.path()).unwrap();
    let mut working_set = WorkingSet::new(storage.clone());
    let mut evm = Evm::<C>::default();
    evm.genesis(config, &mut working_set);

    let root = commit(working_set, storage.clone());

    let mut working_set = WorkingSet::new(storage.clone());
    evm.finalize_hook(&root.into(), &mut working_set.accessory_state());

    let hook_info = HookSoftConfirmationInfo {
        l2_height: 1,
        da_slot_hash: [1u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [2u8; 32],
        pre_state_root: root.to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate: 0,
        timestamp: 0,
    };

    // Pass the same struct to both hooks
    evm.begin_soft_confirmation_hook(&hook_info, &mut working_set);
    evm.end_soft_confirmation_hook(&hook_info, &mut working_set);

    let root = commit(working_set, storage.clone());
    let mut working_set: WorkingSet<<C as Spec>::Storage> = WorkingSet::new(storage.clone());
    evm.finalize_hook(&root.into(), &mut working_set.accessory_state());

    // let mut genesis_state_root = [0u8; 32];
    // genesis_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());

    (evm, working_set)
}

pub(crate) fn commit(
    working_set: WorkingSet<<C as Spec>::Storage>,
    storage: ProverStorage<SnapshotManager>,
) -> [u8; 32] {
    // Save checkpoint
    let mut checkpoint = working_set.checkpoint();

    let (cache_log, mut witness) = checkpoint.freeze();

    let (state_root_transition, authenticated_node_batch, _) = storage
        .compute_state_update(cache_log, &mut witness)
        .expect("jellyfish merkle tree update must succeed");

    let working_set = checkpoint.to_revertable();
    let mut checkpoint = working_set.checkpoint();
    let accessory_log = checkpoint.freeze_non_provable();
    let (offchain_log, _offchain_witness) = checkpoint.freeze_offchain();

    storage.commit(&authenticated_node_batch, &accessory_log, &offchain_log);

    state_root_transition.final_root.0
}

/// Loads the genesis configuration from the given path and pushes the accounts to the evm config
pub(crate) fn config_push_contracts(config: &mut EvmConfig, path: Option<&str>) {
    let mut genesis_config: EvmConfig = read_json_file(Path::new(
        path.unwrap_or("../../resources/test-data/integration-tests/evm.json"),
    ))
    .expect("Failed to read genesis configuration");
    config.data.append(&mut genesis_config.data);
}

pub fn create_contract_message<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
) -> RlpEvmTransaction {
    dev_signer
        .sign_default_transaction(TxKind::Create, contract.byte_code(), nonce, 0)
        .unwrap()
}
pub(crate) fn create_contract_message_with_fee<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
    max_fee_per_gas: u128,
) -> RlpEvmTransaction {
    dev_signer
        .sign_default_transaction_with_fee(
            TxKind::Create,
            contract.byte_code(),
            nonce,
            0,
            max_fee_per_gas,
        )
        .unwrap()
}

pub(crate) fn create_contract_message_with_fee_and_gas_limit<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
    max_fee_per_gas: u128,
    gas_limit: u64,
) -> RlpEvmTransaction {
    dev_signer
        .sign_default_transaction_with_fee_and_gas_limit(
            TxKind::Create,
            contract.byte_code(),
            nonce,
            0,
            max_fee_per_gas,
            gas_limit,
        )
        .unwrap()
}

pub(crate) fn create_contract_transaction<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
) -> RlpEvmTransaction {
    dev_signer
        .sign_default_transaction(TxKind::Create, contract.byte_code(), nonce, 0)
        .unwrap()
}

pub(crate) fn set_arg_message(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    set_arg: u32,
) -> RlpEvmTransaction {
    let contract = SimpleStorageContract::default();

    dev_signer
        .sign_default_transaction(
            TxKind::Call(contract_addr),
            contract.set_call_data(set_arg),
            nonce,
            0,
        )
        .unwrap()
}

pub(crate) fn publish_event_message(
    contract_addr: Address,
    signer: &TestSigner,
    nonce: u64,
    message: String,
) -> RlpEvmTransaction {
    let contract = LogsContract::default();

    signer
        .sign_default_transaction(
            TxKind::Call(contract_addr),
            contract.publish_event(message),
            nonce,
            0,
        )
        .unwrap()
}

pub(crate) fn get_evm_config(
    signer_balance: U256,
    block_gas_limit: Option<u64>,
) -> (EvmConfig, TestSigner, Address) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let contract_addr = address!("819c5497b157177315e1204f52e588b393771719");
    let mut config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: signer_balance,
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        block_gas_limit: block_gas_limit.unwrap_or(ETHEREUM_BLOCK_GAS_LIMIT),
        ..Default::default()
    };
    config_push_contracts(&mut config, None);
    (config, dev_signer, contract_addr)
}

pub(crate) fn get_evm_config_starting_base_fee(
    signer_balance: U256,
    block_gas_limit: Option<u64>,
    starting_base_fee: u64,
) -> (EvmConfig, TestSigner, Address) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let contract_addr = address!("819c5497b157177315e1204f52e588b393771719");
    let mut config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: signer_balance,
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        block_gas_limit: block_gas_limit.unwrap_or(ETHEREUM_BLOCK_GAS_LIMIT),
        starting_base_fee,
        coinbase: PRIORITY_FEE_VAULT,
        ..Default::default()
    };
    config_push_contracts(&mut config, None);
    (config, dev_signer, contract_addr)
}
pub(crate) fn get_evm_test_config() -> EvmConfig {
    let mut config = EvmConfig {
        data: vec![AccountData {
            address: Address::from([1u8; 20]),
            balance: U256::checked_mul(U256::from(1000), U256::pow(U256::from(10), U256::from(18))).unwrap(), // 1000 ETH
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        },
        AccountData {
            address:Address::from([2u8; 20]),
            balance: U256::checked_mul(U256::from(1000),
            U256::pow(U256::from(10), U256::from(18))).unwrap(), // 1000 ETH,
            code_hash: hex!("4e8ee9adb469b245e3a5a8e58e9b733aaa857a9dce1982257531db8a2700aabf").into(),
            code: hex!("60606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a223e05d1461006a578063").into(),
            storage: {
                let mut storage = HashMap::new();
                storage.insert(U256::from(0), U256::from(0x4321));
                storage.insert(
                    U256::from_be_slice(
                        &hex!("6661e9d6d8b923d5bbaab1b96e1dd51ff6ea2a93520fdc9eb75d059238b8c5e9")[..],
                    ),
                    U256::from(8),
                );

                storage
            },
            nonce: 1
        }],
        chain_id: 1000,
        block_gas_limit: reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
        coinbase: Address::from([3u8; 20]),
        limit_contract_code_size: Some(5000),
        starting_base_fee: 1000000000,
        base_fee_params: BaseFeeParams::ethereum(),
        timestamp: 0,
        difficulty: U256::ZERO,
        extra_data: Bytes::default(),
        nonce: 0,
    };
    config_push_contracts(&mut config, None);
    config
}
