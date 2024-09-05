use lazy_static::lazy_static;
use reth_primitives::hex_literal::hex;
use reth_primitives::B256;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::{Module, WorkingSet};
use sov_prover_storage_manager::{new_orphan_storage, SnapshotManager};
use sov_rollup_interface::spec::SpecId;
use sov_state::{DefaultStorageSpec, ProverStorage, Storage};

use crate::{Evm, EvmConfig};

type C = DefaultContext;

lazy_static! {
    pub(crate) static ref GENESIS_HASH: B256 = B256::from(hex!(
        "969d7e2135c5b5ce33d3111f14789b8276941c6ae94467fda5105243be66c9fa"
    ));
    pub(crate) static ref GENESIS_STATE_ROOT: B256 = B256::from(hex!(
        "6deb9a18df7eb41e1f98d2d879482e2f9398d77230dd7074eee5b30ec29704a0"
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
        current_spec: SpecId::Genesis,
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
