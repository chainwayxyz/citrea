use citrea_evm::EvmConfig;
use citrea_primitives::forks::{get_forks, use_network_forks};
use citrea_primitives::EMPTY_TX_ROOT;
use citrea_stf::genesis_config::read_json_file;
use citrea_stf::runtime::{CitreaRuntime, GenesisConfig};
use citrea_stf::test_utils::{commit, init_storage_manager, set_last_l1_hash};
use l2_block_rule_enforcer::L2BlockRuleEnforcerConfig;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_accounts::AccountConfig;
use sov_keys::default_signature::k256_private_key::K256PrivateKey;
use sov_keys::default_signature::K256PublicKey;
use sov_keys::PrivateKey;
use sov_mock_da::MockDaSpec;
use sov_mock_zkvm::MockZkGuest;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::{HookL2BlockInfo, L2BlockError};
use sov_modules_api::{L2Block, SpecId, WorkingSet};
use sov_modules_stf_blueprint::{GenesisParams, StfBlueprint};
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::block::{L2Header, SignedL2Header};
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::stf::StateTransitionError;
use sov_rollup_interface::zk::StorageRootHash;
use sov_rollup_interface::Network;
use sov_state::{ProverStorage, Witness};

type TestStfBlueprint =
    StfBlueprint<DefaultContext, MockDaSpec, CitreaRuntime<DefaultContext, MockDaSpec>>;

fn generate_genesis_config() -> GenesisParams<GenesisConfig<DefaultContext, MockDaSpec>> {
    let accounts_config: AccountConfig =
        read_json_file("../../resources/test-data/integration-tests/accounts.json").unwrap();

    let evm_config: EvmConfig =
        read_json_file("../../resources/test-data/integration-tests/evm.json").unwrap();

    let rule_enforcer_config: L2BlockRuleEnforcerConfig =
        read_json_file("../../resources/test-data/integration-tests/l2_block_rule_enforcer.json")
            .unwrap();

    let genesis = GenesisConfig::<DefaultContext, MockDaSpec> {
        accounts: accounts_config,
        evm: evm_config,
        l2_block_rule_enforcer: rule_enforcer_config,
    };
    GenesisParams { runtime: genesis }
}

#[allow(clippy::too_many_arguments)]
fn create_l2_block(
    stf_blueprint: &mut TestStfBlueprint,
    sequencer_private_key: &K256PrivateKey,
    sequencer_public_key: &K256PublicKey,
    storage_manager: &mut ProverStorageManager,
    prover_storage: ProverStorage,
    height: u64,
    prev_state_root: StorageRootHash,
    block_cache: &mut Vec<(u64, L2Block, Witness, Witness)>,
) -> anyhow::Result<()> {
    let mut working_set = WorkingSet::new(prover_storage.clone());

    let l2_block_info = HookL2BlockInfo {
        l2_height: height,
        pre_state_root: prev_state_root,
        current_spec: SpecId::Tangerine,
        sequencer_pub_key: sequencer_public_key.clone(),
        l1_fee_rate: 128u128,
        timestamp: 10 * (height - 1),
    };

    stf_blueprint
        .begin_l2_block(&mut working_set, &l2_block_info)
        .unwrap();
    stf_blueprint
        .end_l2_block(l2_block_info, &mut working_set)
        .unwrap();
    let l2_block_result =
        stf_blueprint.finalize_l2_block(SpecId::Tangerine, working_set, prover_storage);

    let header = L2Header::new(
        height,
        if block_cache.is_empty() {
            [0; 32]
        } else {
            block_cache.last().unwrap().1.hash()
        },
        l2_block_result.state_root_transition.final_root,
        128u128,
        EMPTY_TX_ROOT,
        10 * (height - 1),
    );
    let digest = header.compute_digest::<<DefaultContext as sov_modules_api::Spec>::Hasher>();
    let hash = Into::<[u8; 32]>::into(digest);
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let l2_block = L2Block {
        header: SignedL2Header::new(header, hash, signature),
        txs: vec![],
    };

    storage_manager.finalize_storage(l2_block_result.change_set);

    block_cache.push((
        height,
        l2_block.clone(),
        l2_block_result.witness,
        l2_block_result.offchain_witness,
    ));

    Ok(())
}

fn init_chain(
    storage_manager: &mut ProverStorageManager,
    stf_blueprint: &TestStfBlueprint,
) -> (StorageRootHash, StorageRootHash) {
    let prover_storage = storage_manager.create_storage_for_next_l2_height();

    use_network_forks(Network::Nightly);

    let genesis_params = generate_genesis_config();

    let (prev_hash, prover_storage) = stf_blueprint.init_chain(prover_storage, genesis_params);
    storage_manager.finalize_storage(prover_storage);

    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    let mut working_set = WorkingSet::new(prover_storage.clone());

    set_last_l1_hash(&mut working_set);
    let (state_root, _, _) = commit(storage_manager, prover_storage, working_set);

    (prev_hash, state_root)
}

#[test]
fn test_wrong_l2_block_signature() {
    let stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    let random_private_key = K256PrivateKey::generate();

    let header = L2Header::new(2, [0; 32], [0; 32], 128u128, EMPTY_TX_ROOT, 10);
    let digest = header.compute_digest::<<DefaultContext as sov_modules_api::Spec>::Hasher>();
    let hash = Into::<[u8; 32]>::into(digest);
    let signature = random_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();

    let l2_block = L2Block {
        header: SignedL2Header::new(header, hash, signature),
        txs: vec![],
    };
    let result = stf_blueprint.verify_l2_block(&l2_block, &sequencer_public_key);

    assert!(matches!(
        result,
        Err(StateTransitionError::L2BlockError(
            L2BlockError::InvalidL2BlockSignature
        ))
    ))
}

#[test]
fn test_wrong_l2_block_hash() {
    let stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

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
    let stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

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

#[test]
fn test_apply_successful_l2_block() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    let prover_storage = storage_manager.create_storage_for_next_l2_height();

    let result = create_l2_block(
        &mut stf_blueprint,
        &sequencer_private_key,
        &sequencer_public_key,
        &mut storage_manager,
        prover_storage,
        1,
        [0; 32],
        &mut vec![],
    );

    assert!(result.is_ok())
}

#[test]
fn test_apply_successful_l2_blocks_from_sequencer_commitments() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    let mut block_cache = vec![];
    let mut prev_state_root = state_root;
    for i in 1..=10 {
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        create_l2_block(
            &mut stf_blueprint,
            &sequencer_private_key,
            &sequencer_public_key,
            &mut storage_manager,
            prover_storage,
            i,
            prev_state_root,
            &mut block_cache,
        )
        .unwrap();

        prev_state_root = block_cache.last().unwrap().1.state_root();
    }

    let mut input: Vec<u8> = vec![];
    // Groups count
    input.extend(&borsh::to_vec(&2u32).unwrap());
    for i in 0..2 {
        // State change count
        input.extend(&borsh::to_vec(&5u32).unwrap());
        // Blocks
        for (height, l2_block, witness, offchain_witness) in &block_cache[i * 5..(i + 1) * 5] {
            input.extend(&borsh::to_vec(&height).unwrap());
            input
                .extend_from_slice(&borsh::to_vec(&(l2_block, witness, offchain_witness)).unwrap());
        }
    }

    // From here on, we establish a new base on which the mockZk guest will run
    // to validate state that has been executed previously.
    let guest = MockZkGuest::new(input);
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();
    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let first_commitment_block_hashes = block_cache[0..5]
        .iter()
        .map(|(_, block, _, _)| block.hash())
        .collect::<Vec<[u8; 32]>>();
    let first_commitment_calculated_root =
        MerkleTree::<Sha256>::from_leaves(&first_commitment_block_hashes)
            .root()
            .unwrap();
    let second_commitment_block_hashes = block_cache[5..]
        .iter()
        .map(|(_, block, _, _)| block.hash())
        .collect::<Vec<[u8; 32]>>();
    let second_commitment_calculated_root =
        MerkleTree::<Sha256>::from_leaves(&second_commitment_block_hashes)
            .root()
            .unwrap();

    let prover_storage = storage_manager.create_storage_for_next_l2_height();

    // Should panic if there is anything wrong. We assume that as long as no panic takes place,
    // everything should be done as it should be.
    stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
        &guest,
        &sequencer_public_key.pub_key.to_sec1_bytes(),
        &state_root,
        prover_storage,
        None,
        vec![
            SequencerCommitment {
                merkle_root: first_commitment_calculated_root,
                index: 1,
                l2_end_block_number: 5,
            },
            SequencerCommitment {
                merkle_root: second_commitment_calculated_root,
                index: 2,
                l2_end_block_number: 10,
            },
        ],
        &[],
        get_forks(),
    );
}

#[test]
fn test_apply_successful_apply_sequencer_commitments_with_previous_commitment() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    let mut block_cache = vec![];
    let mut prev_state_root = state_root;
    for i in 1..=10 {
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        create_l2_block(
            &mut stf_blueprint,
            &sequencer_private_key,
            &sequencer_public_key,
            &mut storage_manager,
            prover_storage,
            i,
            prev_state_root,
            &mut block_cache,
        )
        .unwrap();

        prev_state_root = block_cache.last().unwrap().1.state_root();
    }

    let mut input: Vec<u8> = vec![];
    // Groups count
    input.extend(&borsh::to_vec(&1u32).unwrap());
    for i in 0..2 {
        // State change count
        input.extend(&borsh::to_vec(&5u32).unwrap());
        // Blocks
        for (height, l2_block, witness, offchain_witness) in &block_cache[i * 5..(i + 1) * 5] {
            input.extend(&borsh::to_vec(&height).unwrap());
            input
                .extend_from_slice(&borsh::to_vec(&(l2_block, witness, offchain_witness)).unwrap());
        }
    }

    // From here on, we establish a new base on which the mockZk guest will run
    // to validate state that has been executed previously.
    let guest = MockZkGuest::new(input.clone());
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();
    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let first_commitment_block_hashes = block_cache[0..5]
        .iter()
        .map(|(_, block, _, _)| block.hash())
        .collect::<Vec<[u8; 32]>>();
    let first_commitment_calculated_root =
        MerkleTree::<Sha256>::from_leaves(&first_commitment_block_hashes)
            .root()
            .unwrap();
    let second_commitment_block_hashes = block_cache[5..]
        .iter()
        .map(|(_, block, _, _)| block.hash())
        .collect::<Vec<[u8; 32]>>();
    let second_commitment_calculated_root =
        MerkleTree::<Sha256>::from_leaves(&second_commitment_block_hashes)
            .root()
            .unwrap();

    let prover_storage = storage_manager.create_storage_for_next_l2_height();

    // First, test that the first commitment index should always start at 1
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
            &guest,
            &sequencer_public_key.pub_key.to_sec1_bytes(),
            &state_root,
            prover_storage,
            None,
            vec![SequencerCommitment {
                merkle_root: first_commitment_calculated_root,
                index: 10, // First commitment does NOT start at 1
                l2_end_block_number: 5,
            }],
            &[],
            get_forks(),
        )
    }));
    assert!(result.is_err());

    // Apply first commitment
    let guest = MockZkGuest::new(input.clone());
    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
        &guest,
        &sequencer_public_key.pub_key.to_sec1_bytes(),
        &state_root,
        prover_storage,
        None,
        vec![SequencerCommitment {
            merkle_root: first_commitment_calculated_root,
            index: 1,
            l2_end_block_number: 5,
        }],
        &[],
        get_forks(),
    );

    let guest = MockZkGuest::new(input.clone());
    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    // Should panic since the commitment is index 0 is not allowed
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
            &guest,
            &sequencer_public_key.pub_key.to_sec1_bytes(),
            &state_root,
            prover_storage,
            Some(SequencerCommitment {
                merkle_root: first_commitment_calculated_root,
                index: 0,
                l2_end_block_number: 5,
            }),
            vec![SequencerCommitment {
                merkle_root: second_commitment_calculated_root,
                index: 3,
                l2_end_block_number: 10,
            }],
            &[],
            get_forks(),
        )
    }));
    assert!(result.is_err());

    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    // Should panic since the commitment is index 3 while the next commitment index should be 2.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
            &guest,
            &sequencer_public_key.pub_key.to_sec1_bytes(),
            &state_root,
            prover_storage,
            Some(SequencerCommitment {
                merkle_root: first_commitment_calculated_root,
                index: 1,
                l2_end_block_number: 5,
            }),
            vec![SequencerCommitment {
                merkle_root: second_commitment_calculated_root,
                index: 3,
                l2_end_block_number: 10,
            }],
            &[],
            get_forks(),
        )
    }));

    assert!(result.is_err());

    let mut input: Vec<u8> = vec![];
    // Groups count
    input.extend(&borsh::to_vec(&1u32).unwrap());
    // State change count
    input.extend(&borsh::to_vec(&5u32).unwrap());
    // Blocks
    for (height, l2_block, witness, offchain_witness) in &block_cache[0..5] {
        input.extend(&borsh::to_vec(&height).unwrap());
        input.extend_from_slice(&borsh::to_vec(&(l2_block, witness, offchain_witness)).unwrap());
    }

    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
        &guest,
        &sequencer_public_key.pub_key.to_sec1_bytes(),
        &state_root,
        prover_storage.clone(),
        None,
        vec![SequencerCommitment {
            merkle_root: first_commitment_calculated_root,
            index: 1,
            l2_end_block_number: 5,
        }],
        &[],
        get_forks(),
    );

    storage_manager.finalize_storage(prover_storage);

    let mut input: Vec<u8> = vec![];
    // Groups count
    input.extend(&borsh::to_vec(&1u32).unwrap());
    // State change count
    input.extend(&borsh::to_vec(&5u32).unwrap());
    // Blocks
    for (height, l2_block, witness, offchain_witness) in &block_cache[5..] {
        input.extend(&borsh::to_vec(&height).unwrap());
        input.extend_from_slice(&borsh::to_vec(&(l2_block, witness, offchain_witness)).unwrap());
    }
    // This call has a proper input so expect it to go well.
    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
        &guest,
        &sequencer_public_key.pub_key.to_sec1_bytes(),
        &block_cache[4].1.state_root(),
        prover_storage,
        Some(SequencerCommitment {
            merkle_root: first_commitment_calculated_root,
            index: 1,
            l2_end_block_number: 5,
        }),
        vec![SequencerCommitment {
            merkle_root: second_commitment_calculated_root,
            index: 2,
            l2_end_block_number: 10,
        }],
        &[],
        get_forks(),
    );
}
