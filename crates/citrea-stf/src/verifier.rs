use citrea_evm::{keccak256, Evm, BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS, U256};
use short_header_proof_provider::{ZkShortHeaderProofProviderService, SHORT_HEADER_PROOF_PROVIDER};
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_api::fork::Fork;
use sov_modules_api::{Context, DaSpec};
use sov_modules_stf_blueprint::{ApplySequencerCommitmentsOutput, Runtime, StfBlueprint};
use sov_rollup_interface::zk::batch_proof::input::v3::BatchProofCircuitInputV3Part1;
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;
use sov_rollup_interface::zk::{StorageRootHash, ZkvmGuest};
use sov_rollup_interface::RefCount;
use sov_state::codec::BorshCodec;
use sov_state::storage::{StateValueCodec, Storage, StorageKey, ValueExists};
use sov_state::{ReadWriteLog, Witness};

/// Verifies a state transition
pub struct StateTransitionVerifier<C, Da, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    app: StfBlueprint<C, Da, RT>,
    phantom: std::marker::PhantomData<Da>,
}

impl<C, Da, RT> StateTransitionVerifier<C, Da, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    /// Create a [`StateTransitionVerifier`]
    pub fn new(app: StfBlueprint<C, Da, RT>) -> Self {
        Self {
            app,
            phantom: Default::default(),
        }
    }

    /// Verify the next block
    pub fn run_sequencer_commitments_in_da_slot(
        &mut self,
        guest: &impl ZkvmGuest,
        pre_state: C::Storage,
        sequencer_public_key: &[u8],
        forks: &[Fork],
    ) -> BatchProofCircuitOutput {
        println!("Running sequencer commitments in DA slot");

        let mut data: BatchProofCircuitInputV3Part1 = guest.read_from_host();

        let short_header_proof_provider: ZkShortHeaderProofProviderService<Da> =
            ZkShortHeaderProofProviderService::new(data.short_header_proofs);
        if SHORT_HEADER_PROOF_PROVIDER
            .set(Box::new(short_header_proof_provider))
            .is_err()
        {
            panic!("Short header proof provider already set");
        }

        println!("going into apply_l2_blocks_from_sequencer_commitments");

        let ApplySequencerCommitmentsOutput {
            state_roots,
            state_diff,
            last_l2_height,
            final_l2_block_hash,
            sequencer_commitment_hashes,
            sequencer_commitment_index_range,
            previous_commitment_index,
            previous_commitment_hash,
            cumulative_state_log,
        } = self.app.apply_l2_blocks_from_sequencer_commitments(
            guest,
            sequencer_public_key,
            &data.initial_state_root,
            pre_state.clone(),
            data.previous_sequencer_commitment,
            data.sequencer_commitments,
            &data.cache_prune_l2_heights,
            forks,
        );

        println!("out of apply_l2_blocks_from_sequencer_commitments");

        let last_queried_hash = SHORT_HEADER_PROOF_PROVIDER
            .get()
            .unwrap()
            .take_last_queried_hash();

        let last_l1_hash = if let Some(hash) = last_queried_hash {
            hash
        } else {
            get_last_l1_hash_on_contract::<ZkDefaultContext>(
                cumulative_state_log,
                pre_state,
                &mut data.last_l1_hash_witness,
                *state_roots.last().unwrap(),
            )
        };

        BatchProofCircuitOutput::V3(BatchProofCircuitOutputV3 {
            state_roots,
            final_l2_block_hash,
            state_diff,
            last_l2_height,
            sequencer_commitment_hashes,
            last_l1_hash_on_bitcoin_light_client_contract: last_l1_hash,
            sequencer_commitment_index_range,
            previous_commitment_index,
            previous_commitment_hash,
        })
    }
}

/// Given storage cache a storage and witness
/// returns the last L1 hash on the Bitcoin Light Client contract
/// by first checking the cache for each of the values to be read
/// and then querying the storage if the value is not in cache
///
/// On the native side, the witness is filled with a JMT update proof and the value.
/// On the zk side, the JMT update proof and value is popped and verified.
pub fn get_last_l1_hash_on_contract<C: Context>(
    state_log: ReadWriteLog,
    storage: impl Storage,
    last_l1_hash_witness: &mut Witness,
    final_state_root: StorageRootHash,
) -> [u8; 32] {
    let prefix = {
        let temp_evm = Evm::<C>::default();
        temp_evm.storage.prefix().clone()
    };

    // key for light client contract next l1 height
    let inner_evm_key =
        Evm::<C>::get_storage_address(&BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS, &U256::ZERO);

    let key = StorageKey::new(&prefix, &inner_evm_key, &BorshCodec);

    // first we try to get next L1 height from cache, if it does not exist in cache
    // we need to provide proof with respect to the latest root
    let next_l1_height: U256 = match state_log.get_value(&key.to_cache_key_version(None)) {
        ValueExists::Yes(cache_value) => borsh_deserialize_value(
            cache_value
                .expect("Next L1 height can't be None in cache")
                .value,
        ),
        ValueExists::No => {
            match storage.get_and_prove(&key, last_l1_hash_witness, final_state_root) {
                Some(value) => borsh_deserialize_value(value.into_cache_value().value),
                None => {
                    panic!("Next L1 height should exist in storage");
                }
            }
        }
    };

    // we calculate the corresponding EVM storage slot the last L1 height's hash lives
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(&(next_l1_height - U256::from(1)).to_be_bytes::<32>());
    // counter intuitively the contract stores next block height (expected on setBlockInfo)x
    bytes[32..64].copy_from_slice(&U256::from(1).to_be_bytes::<32>());

    let evm_storage_slot = keccak256(bytes).into();

    let inner_evm_key =
        Evm::<C>::get_storage_address(&BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS, &evm_storage_slot);

    let key = StorageKey::new(&prefix, &inner_evm_key, &BorshCodec);

    // we look for the value inside cache
    // if in cache we don't need to do anything
    // if not in cache we need to provide proof with respect to the latest root
    let last_l1_hash: U256 = match state_log.get_value(&key.to_cache_key_version(None)) {
        ValueExists::Yes(value) => {
            borsh_deserialize_value(value.expect("L1 hash can't be None in cache").value)
        }
        ValueExists::No => {
            match storage.get_and_prove(&key, last_l1_hash_witness, final_state_root) {
                Some(value) => borsh_deserialize_value(value.into_cache_value().value),
                None => {
                    panic!("Last L1 hash should exist in storage");
                }
            }
        }
    };

    last_l1_hash.to_be_bytes()
}

fn borsh_deserialize_value<T>(bytes: RefCount<[u8]>) -> T
where
    BorshCodec: StateValueCodec<T>,
{
    (BorshCodec {}).decode_value_unwrap(&bytes)
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use sov_modules_api::default_context::DefaultContext;
    use sov_modules_api::{StateReaderAndWriter, WorkingSet};
    use sov_prover_storage_manager::ProverStorageManager;
    use sov_state::storage::StorageValue;
    use sov_state::{Config as StorageConfig, ProverStorage, ReadWriteLog, ZkStorage};

    use super::*;

    fn init_storage_manager() -> ProverStorageManager {
        let dir = tempfile::tempdir().unwrap();
        let storage_config = StorageConfig {
            path: dir.path().to_path_buf(),
            db_max_open_files: None,
        };
        ProverStorageManager::new(storage_config).unwrap()
    }

    fn cache_next_l1_height(working_set: &mut WorkingSet<ProverStorage>) {
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

    fn cache_last_l1_hash(working_set: &mut WorkingSet<ProverStorage>) {
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

    fn commit(
        storage_manager: &mut ProverStorageManager,
        prover_storage: ProverStorage,
        working_set: WorkingSet<ProverStorage>,
    ) -> (ReadWriteLog, Witness) {
        // Next block to make sure prover_storage inner DBs have no more than 1 strong reference
        let (state_log, witness) = {
            let mut checkpoint = working_set.checkpoint();
            let (state_log, mut witness) = checkpoint.freeze();

            let (_, state_update, _) = prover_storage
                .compute_state_update(&state_log, &mut witness, true)
                .expect("Storage update must succeed");

            let accessory_log = checkpoint.freeze_non_provable();
            let (offchain_log, _offchain_witness) = checkpoint.freeze_offchain();
            prover_storage.commit(&state_update, &accessory_log, &offchain_log);

            (state_log, witness)
        };
        storage_manager.finalize_storage(prover_storage);

        (state_log, witness)
    }

    #[test]
    #[should_panic(expected = "Next L1 height should exist in storage")]
    fn test_no_l1_next_height_for_get_last_l1_hash_on_contract_failure() {
        // Setup mock storage and witness
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let working_set = WorkingSet::new(prover_storage.clone());
        commit(&mut storage_manager, prover_storage, working_set);
        let final_state_root = [0u8; 32]; // Mock final state root

        // Call the function with mock data that will cause it to fail
        // Simulate a missing key in storage to trigger the failure
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        get_last_l1_hash_on_contract::<ZkDefaultContext>(
            ReadWriteLog::default(),
            prover_storage,
            &mut Witness::default(),
            final_state_root,
        );
    }
    #[test]
    #[should_panic(expected = "Last L1 hash should exist in storage")]
    fn test_no_get_last_l1_hash_on_contract_failure() {
        // Setup mock storage and witness
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let working_set = WorkingSet::new(prover_storage.clone());
        commit(&mut storage_manager, prover_storage, working_set);

        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage.clone());
        cache_next_l1_height(&mut working_set);

        let mut checkpoint = working_set.checkpoint();
        let (state_log, mut witness) = checkpoint.freeze();

        let final_state_root = [0u8; 32]; // Mock final state root

        // Call the function with mock data that will cause it to fail
        // Simulate a missing key in storage to trigger the failure
        get_last_l1_hash_on_contract::<DefaultContext>(
            state_log,
            prover_storage,
            &mut witness,
            final_state_root,
        );
    }

    #[test]
    fn test_get_last_l1_hash_on_contract() {
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage.clone());
        cache_next_l1_height(&mut working_set);
        let _ = commit(&mut storage_manager, prover_storage, working_set);

        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage);
        cache_last_l1_hash(&mut working_set);

        let mut checkpoint = working_set.checkpoint();
        let (state_log, mut witness) = checkpoint.freeze();

        let final_state_root = [0u8; 32]; // Mock final state root

        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        // Call the function with mock data
        let result = get_last_l1_hash_on_contract::<DefaultContext>(
            state_log,
            prover_storage,
            &mut witness,
            final_state_root,
        );

        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);
    }

    #[test]
    fn test_get_last_l1_hash_on_contract_with_commit() {
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage.clone());
        cache_next_l1_height(&mut working_set);
        cache_last_l1_hash(&mut working_set);
        let (state_log, mut witness) = commit(&mut storage_manager, prover_storage, working_set);

        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let final_state_root = [0u8; 32]; // Mock final state root
                                          // Call the function with mock data
        let result = get_last_l1_hash_on_contract::<DefaultContext>(
            state_log,
            prover_storage,
            &mut witness,
            final_state_root,
        );

        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);
    }

    #[test]
    fn test_get_last_l1_hash_on_contract_with_commit_and_verify_with_zkcontext() {
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage.clone());
        cache_next_l1_height(&mut working_set);
        cache_last_l1_hash(&mut working_set);
        let (state_log, mut witness) = commit(&mut storage_manager, prover_storage, working_set);

        let final_state_root = [0u8; 32]; // Mock final state root

        // Call the function with mock data
        let zk_storage = ZkStorage::new();
        let result = get_last_l1_hash_on_contract::<ZkDefaultContext>(
            state_log,
            zk_storage,
            &mut witness,
            final_state_root,
        );

        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);
    }

    #[test]
    fn test_get_last_l1_hash_on_contract_with_commit_and_generate_proof_with_zkcontext() {
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage.clone());
        cache_next_l1_height(&mut working_set);
        cache_last_l1_hash(&mut working_set);

        let (state_log, mut witness) = commit(&mut storage_manager, prover_storage, working_set);
        let prover_storage = storage_manager.create_storage_for_next_l2_height();

        let prefix = Evm::<ZkDefaultContext>::default().storage.prefix().clone();
        let inner_evm_key = Evm::<ZkDefaultContext>::get_storage_address(
            &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
            &U256::ZERO,
        );
        // Append to witness
        let key = StorageKey::new(&prefix, &inner_evm_key, &BorshCodec);
        prover_storage.get_and_prove(&key, &mut witness, [0; 32]);

        let zk_storage = ZkStorage::new();
        // Consume state update hints
        let _ = zk_storage.compute_state_update(&state_log, &mut witness, false);

        let final_state_root = [0u8; 32]; // Mock final state root
        let msg = catch_unwind(AssertUnwindSafe(|| {
            get_last_l1_hash_on_contract::<ZkDefaultContext>(
                // Use an empty ReadWriteLog to force calling `get_and_prove` in
                // zk storage to generate JMT proof inside.
                ReadWriteLog::default(),
                zk_storage,
                &mut witness,
                final_state_root,
            );
        }));

        let error = *msg.unwrap_err().downcast::<String>().unwrap();
        assert!(error.starts_with(
            "JMT proof verification failed: Root hashes do not match. Actual root hash"
        ));
    }
}
