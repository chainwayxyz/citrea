use citrea_primitives::EMPTY_TX_ROOT;
use citrea_stf::runtime::CitreaRuntime;
use sov_keys::default_signature::k256_private_key::K256PrivateKey;
use sov_keys::PrivateKey;
use sov_mock_da::MockDaSpec;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::{HookL2BlockInfo, L2BlockError};
use sov_modules_api::{L2Block, WorkingSet};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::block::{L2Header, SignedL2Header};
use sov_rollup_interface::stf::StateTransitionError;
use sov_state::Config;

fn init_storage_manager() -> ProverStorageManager {
    let dir = tempfile::tempdir().unwrap();
    let storage_config = Config {
        path: dir.path().to_path_buf(),
        db_max_open_files: None,
    };
    ProverStorageManager::new(storage_config).unwrap()
}

#[test]
fn test_wrong_sequencer_public_key() {
    let mut stf_blueprint: StfBlueprint<
        DefaultContext,
        MockDaSpec,
        CitreaRuntime<DefaultContext, MockDaSpec>,
    > = StfBlueprint::<DefaultContext, MockDaSpec, CitreaRuntime<DefaultContext, MockDaSpec>>::default(
    );

    let storage_manager = init_storage_manager();
    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    let mut working_set = WorkingSet::new(prover_storage);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    let random_private_key = K256PrivateKey::generate();
    let random_public_key = random_private_key.pub_key();

    let l2_block_info = HookL2BlockInfo {
        l2_height: 1,
        pre_state_root: [0; 32],
        current_spec: sov_modules_api::SpecId::Kumquat,
        sequencer_pub_key: sequencer_public_key,
        l1_fee_rate: 123,
        timestamp: 1,
    };
    let result = stf_blueprint.begin_l2_block(&random_public_key, &mut working_set, &l2_block_info);
    assert!(matches!(
        result,
        Err(StateTransitionError::L2BlockError(
            L2BlockError::SequencerPublicKeyMismatch
        ))
    ))
}

#[test]
fn test_wrong_l2_block_hash() {
    let stf_blueprint: StfBlueprint<
        DefaultContext,
        MockDaSpec,
        CitreaRuntime<DefaultContext, MockDaSpec>,
    > = StfBlueprint::<DefaultContext, MockDaSpec, CitreaRuntime<DefaultContext, MockDaSpec>>::default(
    );

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    let header = L2Header::new(2, [0; 32], [0; 32], 128u128, EMPTY_TX_ROOT, 10);
    let digest = header.compute_digest::<<DefaultContext as sov_modules_api::Spec>::Hasher>();
    let hash = Into::<[u8; 32]>::into(digest);
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let l2_block = L2Block {
        header: SignedL2Header::new(header, [0; 32], signature),
        txs: vec![],
    };
    let result = stf_blueprint.verify_l2_block(&l2_block, &sequencer_public_key);
    assert!(matches!(
        result,
        Err(StateTransitionError::L2BlockError(
            L2BlockError::InvalidL2BlockHash
        ))
    ))
}

#[test]
fn test_wrong_l2_tx_merkle_root() {
    let stf_blueprint: StfBlueprint<
        DefaultContext,
        MockDaSpec,
        CitreaRuntime<DefaultContext, MockDaSpec>,
    > = StfBlueprint::<DefaultContext, MockDaSpec, CitreaRuntime<DefaultContext, MockDaSpec>>::default(
    );

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    let header = L2Header::new(2, [0; 32], [0; 32], 128u128, [100; 32], 10);
    let digest = header.compute_digest::<<DefaultContext as sov_modules_api::Spec>::Hasher>();
    let hash = Into::<[u8; 32]>::into(digest);
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let l2_block = L2Block {
        header: SignedL2Header::new(header, [0; 32], signature),
        txs: vec![],
    };
    let result = stf_blueprint.verify_l2_block(&l2_block, &sequencer_public_key);
    assert!(matches!(
        result,
        Err(StateTransitionError::L2BlockError(
            L2BlockError::InvalidTxMerkleRoot
        ))
    ))
}
