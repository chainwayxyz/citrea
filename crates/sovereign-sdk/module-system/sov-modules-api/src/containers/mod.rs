mod accessory_map;
mod accessory_value;
mod accessory_vec;

mod offchain_map;

mod map;
mod value;
mod vec;

mod traits;
pub use accessory_map::AccessoryStateMap;
pub use accessory_value::AccessoryStateValue;
pub use accessory_vec::AccessoryStateVec;
pub use map::StateMap;
pub use offchain_map::OffchainStateMap;
pub use traits::{
    StateMapAccessor, StateMapError, StateValueAccessor, StateValueError, StateVecAccessor,
    StateVecError,
};
pub use value::StateValue;
pub use vec::StateVec;

#[cfg(test)]
mod test {
    use sov_modules_core::{StateReaderAndWriter, Storage, StorageKey, StorageValue, WorkingSet};
    use sov_prover_storage_manager::ProverStorageManager;

    #[derive(Clone)]
    struct TestCase {
        key: StorageKey,
        value: StorageValue,
    }

    fn create_tests() -> Vec<TestCase> {
        vec![
            TestCase {
                key: StorageKey::from("key_0"),
                value: StorageValue::from("value_0"),
            },
            TestCase {
                key: StorageKey::from("key_1"),
                value: StorageValue::from("value_1"),
            },
            TestCase {
                key: StorageKey::from("key_2"),
                value: StorageValue::from("value_2"),
            },
            TestCase {
                key: StorageKey::from("key_1"),
                value: StorageValue::from("value_3"),
            },
        ]
    }

    #[test]
    fn test_jmt_storage() {
        let tempdir = tempfile::tempdir().unwrap();
        let tests = create_tests();
        let storage_config = sov_state::config::Config {
            path: tempdir.path().to_path_buf(),
            db_max_open_files: None,
        };
        {
            let storage_manager = ProverStorageManager::new(storage_config.clone()).unwrap();
            let prover_storage = storage_manager.create_storage_for_next_l2_height();
            for test in tests.clone() {
                let mut working_set = WorkingSet::new(prover_storage.clone());

                working_set.set(&test.key, test.value.clone());
                let (state_log, mut witness) = working_set.checkpoint().freeze();
                prover_storage
                    .validate_and_commit(&state_log, &mut witness)
                    .expect("storage is valid");
                assert_eq!(
                    test.value,
                    prover_storage.get(&test.key, &mut witness).unwrap()
                );
            }
            storage_manager.finalize_storage(prover_storage);
        }

        {
            let storage_manager = ProverStorageManager::new(storage_config).unwrap();
            for (test, version) in tests.iter().zip(1..=tests.len()) {
                let storage = storage_manager.create_storage_for_l2_height(version as u64);
                assert_eq!(
                    test.value,
                    storage.get(&test.key, &mut Default::default()).unwrap()
                );
            }
        }
    }

    #[test]
    fn test_restart_lifecycle() {
        let tempdir = tempfile::tempdir().unwrap();
        let storage_config = sov_state::config::Config {
            path: tempdir.path().to_path_buf(),
            db_max_open_files: None,
        };
        {
            let storage_manager = ProverStorageManager::new(storage_config.clone()).unwrap();
            let prover_storage = storage_manager.create_storage_for_next_l2_height();
            assert!(prover_storage.is_empty());
        }

        let key = StorageKey::from("some_key");
        let value = StorageValue::from("some_value");
        // First restart
        {
            let storage_manager = ProverStorageManager::new(storage_config.clone()).unwrap();
            let prover_storage = storage_manager.create_storage_for_next_l2_height();
            assert!(prover_storage.is_empty());
            let mut storage = WorkingSet::new(prover_storage.clone());
            storage.set(&key, value.clone());
            let (state_log, mut witness) = storage.checkpoint().freeze();
            prover_storage
                .validate_and_commit(&state_log, &mut witness)
                .expect("storage is valid");
            storage_manager.finalize_storage(prover_storage);
        }

        // Correctly restart from disk
        {
            let storage_manager = ProverStorageManager::new(storage_config.clone()).unwrap();
            let prover_storage = storage_manager.create_storage_for_next_l2_height();
            assert!(!prover_storage.is_empty());
            assert_eq!(
                value,
                prover_storage.get(&key, &mut Default::default()).unwrap()
            );
        }
    }
}
