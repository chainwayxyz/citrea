#![allow(missing_docs)]
use citrea_evm::{keccak256, Evm, BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS, U256};
use sov_modules_api::default_context::{DefaultContext, ZkDefaultContext};
use sov_modules_api::{StateReaderAndWriter, WorkingSet};
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::codec::BorshCodec;
use sov_state::storage::{Storage, StorageKey, StorageValue};
use sov_state::{Config as StorageConfig, ProverStorage, ReadWriteLog, Witness};

pub fn init_storage_manager() -> ProverStorageManager {
    let dir = tempfile::tempdir().unwrap();
    let storage_config = StorageConfig {
        path: dir.path().to_path_buf(),
        db_max_open_files: None,
    };
    ProverStorageManager::new(storage_config).unwrap()
}

pub fn set_next_l1_height(working_set: &mut WorkingSet<ProverStorage>) {
    // Set Next L1 height for light client contract
    let prefix = Evm::<ZkDefaultContext>::default().storage.prefix().clone();
    let inner_evm_key = Evm::<ZkDefaultContext>::get_storage_address(
        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
        &U256::ZERO,
    );
    let key = StorageKey::new(&prefix, &inner_evm_key, &BorshCodec);
    let value = StorageValue::new(&U256::from(1), &BorshCodec);
    working_set.set(&key, value);
}

pub fn cache_next_l1_height(working_set: &mut WorkingSet<ProverStorage>) {
    // Set Next L1 height for light client contract
    let prefix = Evm::<ZkDefaultContext>::default().storage.prefix().clone();
    let inner_evm_key = Evm::<ZkDefaultContext>::get_storage_address(
        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
        &U256::ZERO,
    );
    let key = StorageKey::new(&prefix, &inner_evm_key, &BorshCodec);
    working_set.get(&key);
}

pub fn set_last_l1_hash(working_set: &mut WorkingSet<ProverStorage>) {
    let prefix = Evm::<DefaultContext>::default().storage.prefix().clone();
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(&U256::from(0).to_be_bytes::<32>());
    bytes[32..64].copy_from_slice(&U256::from(1).to_be_bytes::<32>());
    let evm_storage_slot = keccak256(bytes).into();
    let inner_evm_key = Evm::<DefaultContext>::get_storage_address(
        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
        &evm_storage_slot,
    );
    let key = StorageKey::new(&prefix, &inner_evm_key, &BorshCodec);
    working_set.set(&key, StorageValue::new(&U256::from(1000), &BorshCodec));
}

pub fn cache_last_l1_hash(working_set: &mut WorkingSet<ProverStorage>) {
    let prefix = Evm::<DefaultContext>::default().storage.prefix().clone();
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(&U256::from(0).to_be_bytes::<32>());
    bytes[32..64].copy_from_slice(&U256::from(1).to_be_bytes::<32>());
    let evm_storage_slot = keccak256(bytes).into();
    let inner_evm_key = Evm::<DefaultContext>::get_storage_address(
        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
        &evm_storage_slot,
    );
    let key = StorageKey::new(&prefix, &inner_evm_key, &BorshCodec);
    working_set.get(&key);
}

pub fn commit(
    storage_manager: &mut ProverStorageManager,
    prover_storage: ProverStorage,
    working_set: WorkingSet<ProverStorage>,
) -> (StorageRootHash, ReadWriteLog, Witness) {
    // Next block to make sure prover_storage inner DBs have no more than 1 strong reference
    let (state_root, state_log, witness) = {
        let mut checkpoint = working_set.checkpoint();
        let (state_log, mut witness) = checkpoint.freeze();

        let (state_transition, state_update, _) = prover_storage
            .compute_state_update(&state_log, &mut witness, true)
            .expect("Storage update must succeed");

        let accessory_log = checkpoint.freeze_non_provable();
        let (offchain_log, _offchain_witness) = checkpoint.freeze_offchain();
        prover_storage.commit(&state_update, &accessory_log, &offchain_log);

        (state_transition.final_root, state_log, witness)
    };
    storage_manager.finalize_storage(prover_storage);

    (state_root, state_log, witness)
}
