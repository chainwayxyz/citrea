//! In these tests, you'll see
//!     let prover_storage = storage_manager.create_storage_for_l2_height(7);
//! being used for storage of block 6, which is deu to how to tests were set up.
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
use sov_rollup_interface::zk::batch_proof::input::v3::PrevHashProof;
use sov_rollup_interface::zk::StorageRootHash;
use sov_rollup_interface::Network;
use sov_state::{ProverStorage, Witness};

type TestStfBlueprint =
    StfBlueprint<DefaultContext, MockDaSpec, CitreaRuntime<DefaultContext, MockDaSpec>>;

/// Helper function to extract panic message and assert it contains expected text
fn assert_panic_message_contains(panic_payload: Box<dyn std::any::Any + Send>, expected: &str) {
    let message: &str = if let Some(message) = panic_payload.downcast_ref::<&str>() {
        message
    } else if let Some(message) = panic_payload.downcast_ref::<String>() {
        message
    } else {
        panic!("Unexpected panic payload type");
    };
    assert!(
        message.contains(expected),
        "Expected panic message to contain '{}', but got: '{}'",
        expected,
        message
    );
}

/// Macro to test that code panics with a specific message
macro_rules! assert_panics_with_message {
    ($code:block, $expected_message:expr) => {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $code));
        assert!(result.is_err());
        if let Err(panic_payload) = result {
            assert_panic_message_contains(panic_payload, $expected_message);
        }
    };
}

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
    let hash = header.compute_digest();
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
    let hash = header.compute_digest();
    let signature = random_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();

    let l2_block = L2Block {
        header: SignedL2Header::new(header, hash, signature),
        txs: vec![],
    };
    let result = stf_blueprint.verify_l2_block(&l2_block, &sequencer_public_key, SpecId::Fork3);

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
    let hash = header.compute_digest();
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let l2_block = L2Block {
        header: SignedL2Header::new(header, [0; 32], signature),
        txs: vec![],
    };
    let result = stf_blueprint.verify_l2_block(&l2_block, &sequencer_public_key, SpecId::Fork3);
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
    let hash = header.compute_digest();
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let l2_block = L2Block {
        header: SignedL2Header::new(header, [0; 32], signature),
        txs: vec![],
    };
    let result = stf_blueprint.verify_l2_block(&l2_block, &sequencer_public_key, SpecId::Fork3);
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

    let prover_storage = storage_manager.create_storage_for_l2_height(2);

    // Should panic if there is anything wrong. We assume that as long as no panic takes place,
    // everything should be done as it should be.
    stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
        &guest,
        &sequencer_public_key.pub_key.to_sec1_bytes(),
        Some([0; 32]),
        &state_root,
        prover_storage,
        None,
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
    // TODO: this is input is made to run two sequencer commitments at once. Fix later.
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

    let first_commitment_block_hashes = block_cache[0..5]
        .iter()
        .map(|(_, block, _, _)| block.hash())
        .collect::<Vec<[u8; 32]>>();
    let first_commitment_merkle_tree =
        MerkleTree::<Sha256>::from_leaves(&first_commitment_block_hashes);
    let first_commitment_calculated_root = first_commitment_merkle_tree.root().unwrap();
    let first_commitment_last_block_merkle_proof =
        first_commitment_merkle_tree.proof(&[4]).to_bytes();

    let second_commitment_block_hashes = block_cache[5..]
        .iter()
        .map(|(_, block, _, _)| block.hash())
        .collect::<Vec<[u8; 32]>>();
    let second_commitment_calculated_root =
        MerkleTree::<Sha256>::from_leaves(&second_commitment_block_hashes)
            .root()
            .unwrap();

    let prover_storage = storage_manager.create_storage_for_l2_height(2);

    // First, test that the first commitment index should always start at 1
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &state_root,
                prover_storage,
                None,
                None,
                vec![SequencerCommitment {
                    merkle_root: first_commitment_calculated_root,
                    index: 10, // First commitment does NOT start at 1
                    l2_end_block_number: 5,
                }],
                &[],
                get_forks(),
            )
        },
        "First commitment must be index 1"
    );

    // Apply first commitment
    let guest = MockZkGuest::new(input.clone());
    let prover_storage = storage_manager.create_storage_for_l2_height(2);
    stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
        &guest,
        &sequencer_public_key.pub_key.to_sec1_bytes(),
        Some([0; 32]),
        &state_root,
        prover_storage,
        None,
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
    let prover_storage = storage_manager.create_storage_for_l2_height(2);
    // Should panic since the commitment is index 0 is not allowed
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &block_cache[4].1.header.inner.state_root(),
                prover_storage,
                Some(SequencerCommitment {
                    merkle_root: first_commitment_calculated_root,
                    index: 0,
                    l2_end_block_number: 5,
                }),
                Some(PrevHashProof {
                    merkle_proof_bytes: first_commitment_last_block_merkle_proof.clone(),
                    last_header: block_cache[4].1.header.inner.clone(),
                    prev_sequencer_commitment_start: 1,
                }),
                vec![SequencerCommitment {
                    merkle_root: second_commitment_calculated_root,
                    index: 3,
                    l2_end_block_number: 10,
                }],
                &[],
                get_forks(),
            )
        },
        "Previous sequencer commitment index must be non-zero"
    );

    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_l2_height(7);
    // Should panic since the commitment is index 3 while the next commitment index should be 2.
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &block_cache[4].1.header.inner.state_root(),
                prover_storage,
                Some(SequencerCommitment {
                    merkle_root: first_commitment_calculated_root,
                    index: 1,
                    l2_end_block_number: 5,
                }),
                Some(PrevHashProof {
                    merkle_proof_bytes: first_commitment_last_block_merkle_proof.clone(),
                    last_header: block_cache[4].1.header.inner.clone(),
                    prev_sequencer_commitment_start: 1,
                }),
                vec![SequencerCommitment {
                    merkle_root: second_commitment_calculated_root,
                    index: 3,
                    l2_end_block_number: 10,
                }],
                &[],
                get_forks(),
            )
        },
        "Sequencer commitments must be sequential"
    );

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
    let prover_storage = storage_manager.create_storage_for_l2_height(2);
    stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
        &guest,
        &sequencer_public_key.pub_key.to_sec1_bytes(),
        Some([0; 32]),
        &state_root,
        prover_storage.clone(),
        None,
        None,
        vec![SequencerCommitment {
            merkle_root: first_commitment_calculated_root,
            index: 1,
            l2_end_block_number: 5,
        }],
        &[],
        get_forks(),
    );

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
    let prover_storage = storage_manager.create_storage_for_l2_height(7);
    stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
        &guest,
        &sequencer_public_key.pub_key.to_sec1_bytes(),
        Some([0; 32]),
        &block_cache[4].1.state_root(),
        prover_storage,
        Some(SequencerCommitment {
            merkle_root: first_commitment_calculated_root,
            index: 1,
            l2_end_block_number: 5,
        }),
        Some(PrevHashProof {
            merkle_proof_bytes: first_commitment_last_block_merkle_proof.clone(),
            last_header: block_cache[4].1.header.inner.clone(),
            prev_sequencer_commitment_start: 1,
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

#[test]
fn test_wrong_prev_hash_proof() {
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
    // State change count
    input.extend(&borsh::to_vec(&5u32).unwrap());
    // Blocks
    for (height, l2_block, witness, offchain_witness) in &block_cache[0..5] {
        input.extend(&borsh::to_vec(&height).unwrap());
        input.extend_from_slice(&borsh::to_vec(&(l2_block, witness, offchain_witness)).unwrap());
    }

    let first_commitment_block_hashes = block_cache[0..5]
        .iter()
        .map(|(_, block, _, _)| block.hash())
        .collect::<Vec<[u8; 32]>>();
    let first_commitment_merkle_tree =
        MerkleTree::<Sha256>::from_leaves(&first_commitment_block_hashes);
    let first_commitment_calculated_root = first_commitment_merkle_tree.root().unwrap();
    let first_commitment_last_block_merkle_proof =
        first_commitment_merkle_tree.proof(&[4]).to_bytes();

    let second_commitment_block_hashes = block_cache[5..]
        .iter()
        .map(|(_, block, _, _)| block.hash())
        .collect::<Vec<[u8; 32]>>();
    let second_commitment_calculated_root =
        MerkleTree::<Sha256>::from_leaves(&second_commitment_block_hashes)
            .root()
            .unwrap();

    // Apply first commitment
    // From here on, we establish a new base on which the mockZk guest will run
    // to validate state that has been executed previously.
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let guest = MockZkGuest::new(input.clone());
    let prover_storage = storage_manager.create_storage_for_l2_height(2);
    stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
        &guest,
        &sequencer_public_key.pub_key.to_sec1_bytes(),
        Some([0; 32]),
        &state_root,
        prover_storage,
        None,
        None,
        vec![SequencerCommitment {
            merkle_root: first_commitment_calculated_root,
            index: 1,
            l2_end_block_number: 5,
        }],
        &[],
        get_forks(),
    );

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
    // Correct prev_hash usage
    let guest = MockZkGuest::new(input.clone());
    let prover_storage = storage_manager.create_storage_for_l2_height(7);
    stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
        &guest,
        &sequencer_public_key.pub_key.to_sec1_bytes(),
        Some([0; 32]),
        &block_cache[4].1.state_root(),
        prover_storage,
        Some(SequencerCommitment {
            merkle_root: first_commitment_calculated_root,
            index: 1,
            l2_end_block_number: 5,
        }),
        Some(PrevHashProof {
            merkle_proof_bytes: first_commitment_last_block_merkle_proof.clone(),
            last_header: block_cache[4].1.header.inner.clone(),
            prev_sequencer_commitment_start: 1,
        }),
        vec![SequencerCommitment {
            merkle_root: second_commitment_calculated_root,
            index: 2,
            l2_end_block_number: 10,
        }],
        &[],
        get_forks(),
    );

    // Wrong prev_hash_proof usage, uses wrong last header
    let guest = MockZkGuest::new(input.clone());
    let prover_storage = storage_manager.create_storage_for_l2_height(7);
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &block_cache[4].1.state_root(),
                prover_storage,
                Some(SequencerCommitment {
                    merkle_root: first_commitment_calculated_root,
                    index: 1,
                    l2_end_block_number: 5,
                }),
                Some(PrevHashProof {
                    merkle_proof_bytes: first_commitment_last_block_merkle_proof.clone(),
                    last_header: block_cache[3].1.header.inner.clone(),
                    prev_sequencer_commitment_start: 1,
                }),
                vec![SequencerCommitment {
                    merkle_root: second_commitment_calculated_root,
                    index: 2,
                    l2_end_block_number: 10,
                }],
                &[],
                get_forks(),
            )
        },
        "Initial state root must match the last header state root"
    );
    // Wrong prev_hash_proof usage, uses wrong prev commitment start
    let guest = MockZkGuest::new(input.clone());
    let prover_storage = storage_manager.create_storage_for_l2_height(7);
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &block_cache[4].1.state_root(),
                prover_storage,
                Some(SequencerCommitment {
                    merkle_root: first_commitment_calculated_root,
                    index: 1,
                    l2_end_block_number: 5,
                }),
                Some(PrevHashProof {
                    merkle_proof_bytes: first_commitment_last_block_merkle_proof.clone(),
                    last_header: block_cache[4].1.header.inner.clone(),
                    prev_sequencer_commitment_start: 2,
                }),
                vec![SequencerCommitment {
                    merkle_root: second_commitment_calculated_root,
                    index: 2,
                    l2_end_block_number: 10,
                }],
                &[],
                get_forks(),
            )
        },
        "Prev hash proof must be valid"
    );
}

#[test]
fn test_panic_empty_sequencer_commitments() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    let guest = MockZkGuest::new(vec![]);
    let prover_storage = storage_manager.create_storage_for_next_l2_height();

    // Should panic when sequencer_commitments is empty
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &state_root,
                prover_storage,
                None,
                None,
                vec![], // Empty commitments vector
                &[],
                get_forks(),
            )
        },
        "called `Option::unwrap()` on a `None` value"
    );
}

#[test]
fn test_panic_invalid_sequencer_public_key() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let guest = MockZkGuest::new(vec![]);
    let prover_storage = storage_manager.create_storage_for_next_l2_height();

    // Should panic when sequencer public key is invalid (wrong length)
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &[0u8; 10], // Invalid key length
                Some([0; 32]),
                &state_root,
                prover_storage,
                None,
                None,
                vec![SequencerCommitment {
                    merkle_root: [0; 32],
                    index: 1,
                    l2_end_block_number: 1,
                }],
                &[],
                get_forks(),
            )
        },
        "Sequencer public key must be valid"
    );
}

#[test]
fn test_panic_l2_block_processing_failure() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    // Create a block cache with proper blocks
    let mut block_cache = vec![];
    let mut prev_state_root = state_root;
    for i in 1..=5 {
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

    // Create input with wrong height ordering
    let mut input: Vec<u8> = vec![];
    input.extend(&borsh::to_vec(&1u32).unwrap()); // Groups count
    input.extend(&borsh::to_vec(&2u32).unwrap()); // State change count

    // Add first block correctly
    input.extend(&borsh::to_vec(&1u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(&block_cache[0].1, &block_cache[0].2, &block_cache[0].3)).unwrap(),
    );

    // Add block with height 3 instead of expected height 2 - this should cause a panic
    // Create a new block with height 3 instead of 2
    let header = L2Header::new(
        3,                             // Wrong height - should be 2
        block_cache[0].1.hash(),       // Previous hash should be correct
        block_cache[1].1.state_root(), // Use original state root
        128u128,
        EMPTY_TX_ROOT,
        20, // Use proper timestamp
    );
    let hash = header.compute_digest();
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let fake_block = L2Block {
        header: SignedL2Header::new(header, hash, signature),
        txs: vec![],
    };

    input.extend(&borsh::to_vec(&3u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(&fake_block, &block_cache[1].2, &block_cache[1].3)).unwrap(),
    );

    let commitment_block_hashes = vec![block_cache[0].1.hash(), fake_block.hash()];
    let commitment_calculated_root = MerkleTree::<Sha256>::from_leaves(&commitment_block_hashes)
        .root()
        .unwrap();

    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_l2_height(2);

    // Should panic due to L2 block processing failure (timestamp validation)
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &state_root,
                prover_storage,
                None,
                None,
                vec![SequencerCommitment {
                    merkle_root: commitment_calculated_root,
                    index: 1,
                    l2_end_block_number: 2,
                }],
                &[],
                get_forks(),
            )
        },
        "L2 block height is not equal to the expected height"
    );
}

#[test]
fn test_panic_l2_block_timestamp_validation_failure() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    // Create blocks normally
    let mut block_cache = vec![];
    let mut prev_state_root = state_root;
    for i in 1..=3 {
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

    let header = L2Header::new(
        3,
        block_cache[2].1.prev_hash(),
        block_cache[2].1.state_root(),
        block_cache[2].1.l1_fee_rate(),
        block_cache[2].1.tx_merkle_root(),
        0, // wrong timestamp (should be greater than previous block's timestamp)
    );
    let hash = header.compute_digest();
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let corrupted_l2_block = L2Block {
        header: SignedL2Header::new(header, hash, signature),
        txs: vec![],
    };

    // Create input with corrupted block
    let mut input: Vec<u8> = vec![];
    input.extend(&borsh::to_vec(&1u32).unwrap()); // Groups count
    input.extend(&borsh::to_vec(&3u32).unwrap()); // State change count

    // Add first two blocks correctly
    input.extend(&borsh::to_vec(&1u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(&block_cache[0].1, &block_cache[0].2, &block_cache[0].3)).unwrap(),
    );
    input.extend(&borsh::to_vec(&2u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(&block_cache[1].1, &block_cache[1].2, &block_cache[1].3)).unwrap(),
    );

    // Add corrupted second block
    input.extend(&borsh::to_vec(&3u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(&corrupted_l2_block, &block_cache[2].2, &block_cache[2].3)).unwrap(),
    );

    let commitment_block_hashes = vec![
        block_cache[0].1.hash(),
        block_cache[1].1.hash(),
        corrupted_l2_block.hash(),
    ];
    let commitment_calculated_root = MerkleTree::<Sha256>::from_leaves(&commitment_block_hashes)
        .root()
        .unwrap();

    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_l2_height(2);

    // Should panic due to L2 block processing failure (timestamp validation)
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &state_root,
                prover_storage,
                None,
                None,
                vec![SequencerCommitment {
                    merkle_root: commitment_calculated_root,
                    index: 1,
                    l2_end_block_number: 2,
                }],
                &[],
                get_forks(),
            )
        },
        "L2 block must succeed"
    );
}

#[test]
fn test_panic_l2_block_prev_hash_failure() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    // Create blocks normally
    let mut block_cache = vec![];
    let mut prev_state_root = state_root;
    for i in 1..=3 {
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

    let header = L2Header::new(
        3,
        [1; 32], // Wrong previous hash
        block_cache[2].1.state_root(),
        block_cache[2].1.l1_fee_rate(),
        block_cache[2].1.tx_merkle_root(),
        block_cache[2].1.timestamp(), // Use a later timestamp to avoid TimestampShouldBeGreater error
    );
    let hash = header.compute_digest();
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let corrupted_l2_block = L2Block {
        header: SignedL2Header::new(header, hash, signature),
        txs: vec![],
    };

    // Create input with corrupted block
    let mut input: Vec<u8> = vec![];
    input.extend(&borsh::to_vec(&1u32).unwrap()); // Groups count
    input.extend(&borsh::to_vec(&3u32).unwrap()); // State change count

    // Add first two blocks correctly
    input.extend(&borsh::to_vec(&1u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(&block_cache[0].1, &block_cache[0].2, &block_cache[0].3)).unwrap(),
    );
    input.extend(&borsh::to_vec(&2u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(&block_cache[1].1, &block_cache[1].2, &block_cache[1].3)).unwrap(),
    );

    // Add corrupted second block
    input.extend(&borsh::to_vec(&3u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(&corrupted_l2_block, &block_cache[2].2, &block_cache[2].3)).unwrap(),
    );

    let commitment_block_hashes = vec![
        block_cache[0].1.hash(),
        block_cache[1].1.hash(),
        corrupted_l2_block.hash(),
    ];
    let commitment_calculated_root = MerkleTree::<Sha256>::from_leaves(&commitment_block_hashes)
        .root()
        .unwrap();

    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_l2_height(2);

    // Should panic due to L2 block processing failure (timestamp validation)
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &state_root,
                prover_storage,
                None,
                None,
                vec![SequencerCommitment {
                    merkle_root: commitment_calculated_root,
                    index: 1,
                    l2_end_block_number: 2,
                }],
                &[],
                get_forks(),
            )
        },
        "L2 block previous hash must match the hash of the block before"
    );
}

#[test]
fn test_panic_state_root_assertion_failure() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    // Create a block with wrong state root
    let header = L2Header::new(
        1,
        [0; 32],
        [255; 32], // Wrong state root
        128u128,
        EMPTY_TX_ROOT,
        0,
    );
    let hash = header.compute_digest();
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let corrupted_l2_block = L2Block {
        header: SignedL2Header::new(header, hash, signature),
        txs: vec![],
    };

    // Create proper witness for the block
    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    let mut working_set = WorkingSet::new(prover_storage.clone());
    let l2_block_info = HookL2BlockInfo {
        l2_height: 1,
        pre_state_root: state_root,
        current_spec: SpecId::Tangerine,
        sequencer_pub_key: sequencer_public_key.clone(),
        l1_fee_rate: 128u128,
        timestamp: 0,
    };

    stf_blueprint
        .begin_l2_block(&mut working_set, &l2_block_info)
        .unwrap();
    stf_blueprint
        .end_l2_block(l2_block_info, &mut working_set)
        .unwrap();
    let l2_block_result =
        stf_blueprint.finalize_l2_block(SpecId::Tangerine, working_set, prover_storage);

    // Create input with corrupted block
    let mut input: Vec<u8> = vec![];
    input.extend(&borsh::to_vec(&1u32).unwrap()); // Groups count
    input.extend(&borsh::to_vec(&1u32).unwrap()); // State change count
    input.extend(&borsh::to_vec(&1u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(
            &corrupted_l2_block,
            &l2_block_result.witness,
            &l2_block_result.offchain_witness,
        ))
        .unwrap(),
    );

    let commitment_block_hashes = vec![corrupted_l2_block.hash()];
    let commitment_calculated_root = MerkleTree::<Sha256>::from_leaves(&commitment_block_hashes)
        .root()
        .unwrap();

    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_l2_height(2);

    // Should panic due to state root assertion failure
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &state_root,
                prover_storage,
                None,
                None,
                vec![SequencerCommitment {
                    merkle_root: commitment_calculated_root,
                    index: 1,
                    l2_end_block_number: 1,
                }],
                &[],
                get_forks(),
            )
        },
        "assertion `left == right` failed"
    );
}

#[test]
fn test_panic_merkle_root_assertion_failure() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    // Create a proper block
    let mut block_cache = vec![];
    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    create_l2_block(
        &mut stf_blueprint,
        &sequencer_private_key,
        &sequencer_public_key,
        &mut storage_manager,
        prover_storage,
        1,
        state_root,
        &mut block_cache,
    )
    .unwrap();

    // Create input with proper block
    let mut input: Vec<u8> = vec![];
    input.extend(&borsh::to_vec(&1u32).unwrap()); // Groups count
    input.extend(&borsh::to_vec(&1u32).unwrap()); // State change count
    input.extend(&borsh::to_vec(&1u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(&block_cache[0].1, &block_cache[0].2, &block_cache[0].3)).unwrap(),
    );

    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_l2_height(2);

    // Should panic due to merkle root assertion failure
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &state_root,
                prover_storage,
                None,
                None,
                vec![SequencerCommitment {
                    merkle_root: [255; 32], // Wrong merkle root
                    index: 1,
                    l2_end_block_number: 1,
                }],
                &[],
                get_forks(),
            )
        },
        "assertion `left == right` failed"
    );
}

#[test]
fn test_panic_l2_block_height_jump() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    // Create blocks
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

    let first_commitment_block_hashes = block_cache[0..5]
        .iter()
        .map(|(_, block, _, _)| block.hash())
        .collect::<Vec<[u8; 32]>>();
    let first_commitment_calculated_root =
        MerkleTree::<Sha256>::from_leaves(&first_commitment_block_hashes)
            .root()
            .unwrap();

    // Now test with actual non-sequential commitments
    let mut input: Vec<u8> = vec![];
    input.extend(&borsh::to_vec(&2u32).unwrap()); // Groups count

    // First group: blocks 1-5
    input.extend(&borsh::to_vec(&5u32).unwrap());
    for (height, l2_block, witness, offchain_witness) in &block_cache[0..5] {
        input.extend(&borsh::to_vec(&height).unwrap());
        input.extend_from_slice(&borsh::to_vec(&(l2_block, witness, offchain_witness)).unwrap());
    }

    // Second group: blocks 8-10 (skipping 6-7, making it non-sequential)
    input.extend(&borsh::to_vec(&3u32).unwrap());
    for (height, l2_block, witness, offchain_witness) in &block_cache[7..10] {
        input.extend(&borsh::to_vec(&height).unwrap());
        input.extend_from_slice(&borsh::to_vec(&(l2_block, witness, offchain_witness)).unwrap());
    }

    let second_commitment_block_hashes = block_cache[7..10]
        .iter()
        .map(|(_, block, _, _)| block.hash())
        .collect::<Vec<[u8; 32]>>();
    let second_commitment_calculated_root =
        MerkleTree::<Sha256>::from_leaves(&second_commitment_block_hashes)
            .root()
            .unwrap();

    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_l2_height(2);

    // Should panic due to L2 block execution failure (timestamp validation)
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &state_root,
                prover_storage,
                None,
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
                        l2_end_block_number: 10, // Should be 8 if sequential
                    },
                ],
                &[],
                get_forks(),
            )
        },
        "L2 block height is not equal to the expected height"
    );
}

#[test]
fn test_panic_state_root_mismatch_assertion() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

    let mut storage_manager = init_storage_manager();
    let (_, state_root) = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    // Create a block with extremely high gas fee rate which could cause issues in processing
    let header = L2Header::new(
        1,
        [0; 32],
        state_root, // Use correct initial state root
        u128::MAX,  // Extremely high gas fee rate that could cause overflow issues
        EMPTY_TX_ROOT,
        0,
    );
    let hash = header.compute_digest();
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let problematic_block = L2Block {
        header: SignedL2Header::new(header, hash, signature),
        txs: vec![],
    };

    // Create proper witness for the block
    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    let mut working_set = WorkingSet::new(prover_storage.clone());
    let l2_block_info = HookL2BlockInfo {
        l2_height: 1,
        pre_state_root: state_root,
        current_spec: SpecId::Tangerine,
        sequencer_pub_key: sequencer_public_key.clone(),
        l1_fee_rate: u128::MAX, // This should match the block's gas fee rate
        timestamp: 0,
    };

    stf_blueprint
        .begin_l2_block(&mut working_set, &l2_block_info)
        .unwrap();
    stf_blueprint
        .end_l2_block(l2_block_info, &mut working_set)
        .unwrap();
    let l2_block_result =
        stf_blueprint.finalize_l2_block(SpecId::Tangerine, working_set, prover_storage);

    // Create input with the problematic block
    let mut input: Vec<u8> = vec![];
    input.extend(&borsh::to_vec(&1u32).unwrap()); // Groups count
    input.extend(&borsh::to_vec(&1u32).unwrap()); // State change count
    input.extend(&borsh::to_vec(&1u64).unwrap());
    input.extend_from_slice(
        &borsh::to_vec(&(
            &problematic_block,
            &l2_block_result.witness,
            &l2_block_result.offchain_witness,
        ))
        .unwrap(),
    );

    let commitment_block_hashes = vec![problematic_block.hash()];
    let commitment_calculated_root = MerkleTree::<Sha256>::from_leaves(&commitment_block_hashes)
        .root()
        .unwrap();

    let guest = MockZkGuest::new(input);
    let prover_storage = storage_manager.create_storage_for_l2_height(2);

    // This should panic due to state root assertion failure
    assert_panics_with_message!(
        {
            stf_blueprint.apply_l2_blocks_from_sequencer_commitments(
                &guest,
                &sequencer_public_key.pub_key.to_sec1_bytes(),
                Some([0; 32]),
                &state_root,
                prover_storage,
                None,
                None,
                vec![SequencerCommitment {
                    merkle_root: commitment_calculated_root,
                    index: 1,
                    l2_end_block_number: 1,
                }],
                &[],
                get_forks(),
            )
        },
        "assertion `left == right` failed"
    );
}
