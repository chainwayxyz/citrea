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

    use sov_modules_api::default_context::DefaultContext;
    use sov_modules_api::WorkingSet;
    use sov_state::{ReadWriteLog, ZkStorage};

    use super::*;
    use crate::test_utils::{
        cache_last_l1_hash, cache_next_l1_height, commit, init_storage_manager, set_last_l1_hash,
        set_next_l1_height,
    };

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
        set_next_l1_height(&mut working_set);

        let mut checkpoint = working_set.checkpoint();
        let (state_log, _) = checkpoint.freeze();

        let final_state_root = [0u8; 32]; // Mock final state root

        // Call the function with mock data that will cause it to fail
        // Simulate a missing key in storage to trigger the failure
        get_last_l1_hash_on_contract::<DefaultContext>(
            state_log,
            prover_storage,
            &mut Witness::default(), // witness does not matter here
            final_state_root,
        );
    }

    #[test]
    fn test_get_last_l1_hash_on_contract() {
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage.clone());
        set_last_l1_hash(&mut working_set);
        set_next_l1_height(&mut working_set);
        let _ = commit(&mut storage_manager, prover_storage, working_set);

        // Only height is cached
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage);

        cache_next_l1_height(&mut working_set);
        let state_log = working_set.checkpoint().freeze().0;

        let final_state_root = [0u8; 32]; // Mock final state root

        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        // Call the function with mock data
        let result = get_last_l1_hash_on_contract::<DefaultContext>(
            state_log,
            prover_storage,
            &mut Witness::default(), // witness does not matter here
            final_state_root,
        );

        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);

        // Only hash is cached
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage);

        cache_last_l1_hash(&mut working_set);
        let state_log = working_set.checkpoint().freeze().0;

        let final_state_root = [0u8; 32]; // Mock final state root

        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        // Call the function with mock data
        let result = get_last_l1_hash_on_contract::<DefaultContext>(
            state_log,
            prover_storage,
            &mut Witness::default(), // witness does not matter here
            final_state_root,
        );

        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);

        // Boths is cached
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage);

        cache_next_l1_height(&mut working_set);
        cache_last_l1_hash(&mut working_set);
        let state_log = working_set.checkpoint().freeze().0;

        let final_state_root = [0u8; 32]; // Mock final state root

        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        // Call the function with mock data
        let result = get_last_l1_hash_on_contract::<DefaultContext>(
            state_log,
            prover_storage,
            &mut Witness::default(), // witness does not matter here
            final_state_root,
        );

        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);
    }

    #[test]
    fn test_get_last_l1_hash_on_contract_with_no_cache() {
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage.clone());
        set_next_l1_height(&mut working_set);
        set_last_l1_hash(&mut working_set);
        let (_, _, _) = commit(&mut storage_manager, prover_storage, working_set);

        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let final_state_root = [0u8; 32]; // Mock final state root

        // Shows that no cache works
        let result = get_last_l1_hash_on_contract::<DefaultContext>(
            ReadWriteLog::default(),
            prover_storage,
            &mut Witness::default(), // witness does not matter here
            final_state_root,
        );

        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);
    }

    #[test]
    fn test_get_last_l1_hash_on_contract_and_verify_with_zkcontext() {
        // set up storage
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage.clone());
        set_next_l1_height(&mut working_set);
        set_last_l1_hash(&mut working_set);
        let (_, _, _) = commit(&mut storage_manager, prover_storage, working_set);

        // try the native --> zk flow without the values being in cache
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut witness = Witness::default();

        // root was found by running the test
        let state_root = [
            7, 86, 209, 84, 188, 43, 20, 206, 77, 83, 166, 176, 24, 255, 207, 214, 80, 9, 121, 121,
            224, 119, 248, 189, 79, 241, 89, 51, 108, 134, 95, 82,
        ];

        // accumulate state reads on witness
        let _ = get_last_l1_hash_on_contract::<DefaultContext>(
            ReadWriteLog::default(),
            prover_storage,
            &mut witness,
            state_root,
        );

        // Call the function with witness accumulated in the previous step
        let zk_storage = ZkStorage::new();
        let result = get_last_l1_hash_on_contract::<ZkDefaultContext>(
            ReadWriteLog::default(),
            zk_storage,
            &mut witness,
            state_root,
        );

        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);

        // Let's see if native --> zk flow works when the values are in cache

        let get_read_write_log_with_both_cached = || {
            let prover_storage = storage_manager.create_storage_for_next_l2_height();
            let mut working_set = WorkingSet::new(prover_storage.clone());
            cache_next_l1_height(&mut working_set);
            cache_last_l1_hash(&mut working_set);

            let log = working_set.checkpoint().freeze().0;

            assert_eq!(log.ordered_reads().len(), 2);

            log
        };

        let mut witness = Witness::default();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();

        // accumulate state reads on witness
        let _ = get_last_l1_hash_on_contract::<DefaultContext>(
            get_read_write_log_with_both_cached(),
            prover_storage,
            &mut witness,
            state_root,
        );

        // Call the function with witness accumulated in the previous step
        let zk_storage = ZkStorage::new();
        let result = get_last_l1_hash_on_contract::<ZkDefaultContext>(
            get_read_write_log_with_both_cached(),
            zk_storage,
            &mut witness,
            state_root,
        );
        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);

        // only height is cached
        let get_read_write_log_with_height_cached = || {
            let prover_storage = storage_manager.create_storage_for_next_l2_height();
            let mut working_set = WorkingSet::new(prover_storage.clone());
            cache_next_l1_height(&mut working_set);

            let log = working_set.checkpoint().freeze().0;

            assert_eq!(log.ordered_reads().len(), 1);

            log
        };

        let mut witness = Witness::default();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();

        // accumulate state reads on witness
        let _ = get_last_l1_hash_on_contract::<DefaultContext>(
            get_read_write_log_with_height_cached(),
            prover_storage,
            &mut witness,
            state_root,
        );

        // Call the function with witness accumulated in the previous step
        let zk_storage = ZkStorage::new();
        let result = get_last_l1_hash_on_contract::<ZkDefaultContext>(
            get_read_write_log_with_height_cached(),
            zk_storage,
            &mut witness,
            state_root,
        );
        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);

        // only hash is cached
        let get_read_write_log_with_hash_cached = || {
            let prover_storage = storage_manager.create_storage_for_next_l2_height();
            let mut working_set = WorkingSet::new(prover_storage.clone());
            cache_last_l1_hash(&mut working_set);

            let log = working_set.checkpoint().freeze().0;

            assert_eq!(log.ordered_reads().len(), 1);

            log
        };

        let mut witness = Witness::default();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();

        // accumulate state reads on witness
        let _ = get_last_l1_hash_on_contract::<DefaultContext>(
            get_read_write_log_with_hash_cached(),
            prover_storage,
            &mut witness,
            state_root,
        );

        // Call the function with witness accumulated in the previous step
        let zk_storage = ZkStorage::new();
        let result = get_last_l1_hash_on_contract::<ZkDefaultContext>(
            get_read_write_log_with_hash_cached(),
            zk_storage,
            &mut witness,
            state_root,
        );
        // Assert the result is as expected (mocked value)
        assert_eq!(result, U256::from(1000).to_be_bytes::<32>(),);
    }

    #[test]
    #[should_panic(expected = "JMT proof verification failed: Root hashes do not match.")]
    fn test_get_last_l1_hash_on_contract_fail_in_zkcontext_by_incorrect_update_proof() {
        // set up storage
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage.clone());
        set_next_l1_height(&mut working_set);
        set_last_l1_hash(&mut working_set);
        let (_, _, _) = commit(&mut storage_manager, prover_storage, working_set);

        // try the native --> zk flow without the values being in cache
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut witness = Witness::default();

        // incorrect state root known by zk
        // so that we can make the read proofs fail
        let false_state_root = [0xa; 32];

        // accumulate state reads on witness
        let _ = get_last_l1_hash_on_contract::<DefaultContext>(
            ReadWriteLog::default(),
            prover_storage,
            &mut witness,
            false_state_root,
        );

        // Call the function with witness accumulated in the previous step
        let zk_storage = ZkStorage::new();
        get_last_l1_hash_on_contract::<ZkDefaultContext>(
            ReadWriteLog::default(),
            zk_storage,
            &mut witness,
            false_state_root,
        );
    }

    #[test]
    #[should_panic(expected = "JMT proof verification failed: Value hashes do not match.")]
    fn test_get_last_l1_hash_on_contract_fail_in_zkcontext_by_incorrect_value_supplied() {
        // set up storage
        let mut storage_manager = init_storage_manager();
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut working_set = WorkingSet::new(prover_storage.clone());
        set_next_l1_height(&mut working_set);
        set_last_l1_hash(&mut working_set);
        let (_, _, _) = commit(&mut storage_manager, prover_storage, working_set);

        // try the native --> zk flow without the values being in cache
        let prover_storage = storage_manager.create_storage_for_next_l2_height();
        let mut witness = Witness::default();

        // actual state root
        let state_root = [
            7, 86, 209, 84, 188, 43, 20, 206, 77, 83, 166, 176, 24, 255, 207, 214, 80, 9, 121, 121,
            224, 119, 248, 189, 79, 241, 89, 51, 108, 134, 95, 82,
        ];

        // accumulate state reads on witness
        let _ = get_last_l1_hash_on_contract::<DefaultContext>(
            ReadWriteLog::default(),
            prover_storage,
            &mut witness,
            state_root,
        );

        let mut hints = witness.get_hints();

        let val = hints.get_mut(0).unwrap();
        val[5] = 2; // first read value U256::from(2) instead of U256::from(1) now

        assert_eq!(hints.len(), 4);

        let mut witness = Witness::from(hints);

        // Call the function with witness accumulated in the previous step
        let zk_storage = ZkStorage::new();
        get_last_l1_hash_on_contract::<ZkDefaultContext>(
            ReadWriteLog::default(),
            zk_storage,
            &mut witness,
            state_root,
        );
    }
}
