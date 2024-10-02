use std::path::Path;

use lazy_static::lazy_static;
use reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT;
use reth_primitives::hex_literal::hex;
use reth_primitives::{address, Address, Bytes, TxKind, B256};
use revm::primitives::{SpecId, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::{Module, WorkingSet};
use sov_prover_storage_manager::{new_orphan_storage, SnapshotManager};
use sov_rollup_interface::spec::SpecId as SovSpecId;
use sov_state::{DefaultStorageSpec, ProverStorage, Storage};
use sov_stf_runner::read_json_file;

use crate::smart_contracts::{LogsContract, SimpleStorageContract, TestContract};
use crate::tests::test_signer::TestSigner;
use crate::{AccountData, Evm, EvmConfig, RlpEvmTransaction, PRIORITY_FEE_VAULT};

type C = DefaultContext;

lazy_static! {
    pub(crate) static ref GENESIS_HASH: B256 = B256::from(hex!(
        "9fcaf6e03bf17a3372e03c5f3aa293dee54f73545462f82ba7875710da4604d5"
    ));
    pub(crate) static ref GENESIS_STATE_ROOT: B256 = B256::from(hex!(
        "5a4c1a83d16c771fa4221e0353ef5e2af558dbe11ce429e677914292428dec1c"
    ));
}

pub(crate) fn get_evm_with_storage(
    config: &EvmConfig,
) -> (
    Evm<C>,
    WorkingSet<DefaultContext>,
    ProverStorage<DefaultStorageSpec, SnapshotManager>,
) {
    let tmpdir = tempfile::tempdir().unwrap();
    let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
    let mut working_set = WorkingSet::new(prover_storage.clone());
    let evm = Evm::<C>::default();
    evm.genesis(config, &mut working_set).unwrap();

    let mut genesis_state_root = [0u8; 32];
    genesis_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());

    evm.finalize_hook(
        &genesis_state_root.into(),
        &mut working_set.accessory_state(),
    );
    (evm, working_set, prover_storage)
}
pub(crate) fn get_evm(config: &EvmConfig) -> (Evm<C>, WorkingSet<C>) {
    let tmpdir = tempfile::tempdir().unwrap();
    let storage = new_orphan_storage(tmpdir.path()).unwrap();
    let mut working_set = WorkingSet::new(storage.clone());
    let mut evm = Evm::<C>::default();
    evm.genesis(config, &mut working_set).unwrap();

    let root = commit(working_set, storage.clone());

    let mut working_set: WorkingSet<C> = WorkingSet::new(storage.clone());
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
    let mut working_set: WorkingSet<C> = WorkingSet::new(storage.clone());
    evm.finalize_hook(&root.into(), &mut working_set.accessory_state());

    // let mut genesis_state_root = [0u8; 32];
    // genesis_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());

    (evm, working_set)
}

pub(crate) fn commit(
    working_set: WorkingSet<C>,
    storage: ProverStorage<DefaultStorageSpec, SnapshotManager>,
) -> [u8; 32] {
    // Save checkpoint
    let mut checkpoint = working_set.checkpoint();

    let (cache_log, mut witness) = checkpoint.freeze();

    let (root, authenticated_node_batch, _) = storage
        .compute_state_update(cache_log, &mut witness)
        .expect("jellyfish merkle tree update must succeed");

    let working_set = checkpoint.to_revertable();

    let accessory_log = working_set.checkpoint().freeze_non_provable();

    storage.commit(&authenticated_node_batch, &accessory_log);

    root.0
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
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
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
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        block_gas_limit: block_gas_limit.unwrap_or(ETHEREUM_BLOCK_GAS_LIMIT),
        starting_base_fee,
        coinbase: PRIORITY_FEE_VAULT,
        ..Default::default()
    };
    config_push_contracts(&mut config, None);
    (config, dev_signer, contract_addr)
}
