use citrea_evm::EvmConfig;
use citrea_primitives::forks::use_network_forks;
use citrea_primitives::EMPTY_TX_ROOT;
use citrea_stf::runtime::{CitreaRuntime, GenesisConfig};
use citrea_stf::test_utils::{commit, init_storage_manager, set_last_l1_hash};
use l2_block_rule_enforcer::L2BlockRuleEnforcerConfig;
use serde_json::json;
use sov_accounts::AccountConfig;
use sov_keys::default_signature::k256_private_key::K256PrivateKey;
use sov_keys::PrivateKey;
use sov_mock_da::MockDaSpec;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::{HookL2BlockInfo, L2BlockError};
use sov_modules_api::{L2Block, SpecId, WorkingSet};
use sov_modules_stf_blueprint::{GenesisParams, StfBlueprint};
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::block::{L2Header, SignedL2Header};
use sov_rollup_interface::stf::StateTransitionError;
use sov_rollup_interface::Network;
use sov_state::Witness;

type TestStfBlueprint =
    StfBlueprint<DefaultContext, MockDaSpec, CitreaRuntime<DefaultContext, MockDaSpec>>;

fn generate_genesis_config() -> GenesisParams<GenesisConfig<DefaultContext, MockDaSpec>> {
    let accounts_config = AccountConfig { pub_keys: vec![] };
    let evm_config: EvmConfig = serde_json::from_value(json!({
        "data": [],
        "chain_id": 5655,
        "limit_contract_code_size": 24576,
        "coinbase": "0x3100000000000000000000000000000000000005",
        "starting_base_fee": 1000000000,
        "block_gas_limit": 30000000,
        "base_fee_params": {
            "max_change_denominator": 8,
            "elasticity_multiplier": 2
        },
        "difficulty": 0,
        "extra_data": "0x",
        "timestamp": 0,
        "nonce": 0
    }))
    .unwrap();

    let rule_enforcer_config: L2BlockRuleEnforcerConfig = serde_json::from_value(json!({
        "max_l2_blocks_per_l1": 86400,
        "authority": "sov1kqrxxkwkf7t7kfuegllwkzp6jc6r6h66pgkfe7pggtm0gayl756qku2u5p"
    }))
    .unwrap();

    let genesis = GenesisConfig::<DefaultContext, MockDaSpec> {
        accounts: accounts_config,
        evm: evm_config,
        l2_block_rule_enforcer: rule_enforcer_config,
    };
    GenesisParams { runtime: genesis }
}

fn init_chain(
    storage_manager: &mut ProverStorageManager,
    stf_blueprint: &TestStfBlueprint,
) -> [u8; 32] {
    let prover_storage = storage_manager.create_storage_for_next_l2_height();

    use_network_forks(Network::Nightly);

    let genesis_params = generate_genesis_config();

    let (prev_hash, prover_storage) = stf_blueprint.init_chain(prover_storage, genesis_params);
    storage_manager.finalize_storage(prover_storage);

    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    let mut working_set = WorkingSet::new(prover_storage.clone());

    set_last_l1_hash(&mut working_set);
    let (_, _) = commit(storage_manager, prover_storage, working_set);

    prev_hash
}

#[test]
fn test_wrong_sequencer_public_key() {
    let mut stf_blueprint: TestStfBlueprint = TestStfBlueprint::default();

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
    let prev_hash = init_chain(&mut storage_manager, &stf_blueprint);

    let sequencer_private_key = K256PrivateKey::generate();
    let sequencer_public_key = sequencer_private_key.pub_key();

    let prover_storage = storage_manager.create_storage_for_next_l2_height();
    let header = L2Header::new(1, prev_hash, [0; 32], 128u128, EMPTY_TX_ROOT, 10);
    let digest = header.compute_digest::<<DefaultContext as sov_modules_api::Spec>::Hasher>();
    let hash = Into::<[u8; 32]>::into(digest);
    let signature = sequencer_private_key.sign(&hash);
    let signature = borsh::to_vec(&signature).unwrap();
    let l2_block = L2Block {
        header: SignedL2Header::new(header, hash, signature),
        txs: vec![],
    };
    let result = stf_blueprint.apply_l2_block(
        SpecId::Kumquat,
        &sequencer_public_key,
        &[0; 32],
        prover_storage,
        None,
        None,
        Witness::default(),
        Witness::default(),
        &l2_block,
    );
    assert!(matches!(result, Ok(_)))
}
