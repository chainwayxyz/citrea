use sov_modules_core::{StateReaderAndWriter, StorageKey, StorageValue, WorkingSet};
use sov_prover_storage_manager::new_orphan_storage;
use sov_state::codec::BcsCodec;

#[test]
fn test_workingset_get() {
    let tempdir = tempfile::tempdir().unwrap();
    let codec = BcsCodec {};
    let storage = new_orphan_storage(tempdir.path()).unwrap();

    let prefix = sov_modules_core::Prefix::new(vec![1, 2, 3]);
    let storage_key = StorageKey::new(&prefix, &vec![4, 5, 6], &codec);
    let storage_value = StorageValue::new(&vec![7, 8, 9], &codec);

    let mut working_set = WorkingSet::new(storage.clone());
    working_set.set(&storage_key, storage_value.clone());

    assert_eq!(Some(storage_value), working_set.get(&storage_key));
}
