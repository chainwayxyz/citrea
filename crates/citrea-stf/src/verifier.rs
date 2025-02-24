use citrea_evm::{keccak256, Evm, BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS, U256};
use short_header_proof_provider::{ZkShortHeaderProofProviderService, SHORT_HEADER_PROOF_PROVIDER};
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_api::fork::Fork;
use sov_modules_api::{Context, DaSpec};
use sov_modules_stf_blueprint::{ApplySequencerCommitmentsOutput, Runtime, StfBlueprint};
use sov_rollup_interface::zk::batch_proof::input::v3::BatchProofCircuitInputV3Part1;
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::{StorageRootHash, ZkvmGuest};
use sov_rollup_interface::RefCount;
use sov_state::codec::{BcsCodec, BorshCodec};
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
        sequencer_k256_public_key: &[u8],
        forks: &[Fork],
    ) -> BatchProofCircuitOutputV3 {
        println!("Running sequencer commitments in DA slot");

        let mut data: BatchProofCircuitInputV3Part1<Da> = guest.read_from_host();

        let short_header_proof_provider: ZkShortHeaderProofProviderService<Da> =
            ZkShortHeaderProofProviderService::new(data.short_header_proofs);
        if SHORT_HEADER_PROOF_PROVIDER
            .set(Box::new(short_header_proof_provider))
            .is_err()
        {
            panic!("Short header proof provider already set");
        }

        println!("going into apply_soft_confirmations_from_sequencer_commitments");

        let ApplySequencerCommitmentsOutput {
            final_state_root,
            state_diff,
            last_l2_height,
            final_soft_confirmation_hash,
            sequencer_commitment_merkle_roots,
            cumulative_state_log,
        } = self
            .app
            .apply_soft_confirmations_from_sequencer_commitments(
                guest,
                sequencer_public_key,
                sequencer_k256_public_key,
                &data.initial_state_root,
                pre_state.clone(),
                data.sequencer_commitments,
                data.da_block_headers_of_soft_confirmations,
                &data.cache_prune_l2_heights,
                forks,
            );

        println!("out of apply_soft_confirmations_from_sequencer_commitments");

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
                final_state_root,
            )
        };

        BatchProofCircuitOutputV3 {
            initial_state_root: data.initial_state_root,
            final_state_root,
            final_soft_confirmation_hash,
            state_diff,
            last_l2_height,
            sequencer_commitment_merkle_roots,
            last_l1_hash_on_bitcoin_light_client_contract: last_l1_hash,
        }
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
    let next_l1_height: U256 = match state_log.get_value(&key.clone().into_cache_key()) {
        ValueExists::Yes(cache_value) => borsh_deserialize_value(
            cache_value
                .expect("Next L1 height can't be None in cache")
                .value,
        ),
        ValueExists::No => {
            match storage.get_and_prove(&key, last_l1_hash_witness, final_state_root) {
                Some(value) => borsh_deserialize_value(value.into_cache_value().value),
                None => {
                    // If this is the first proof in Fork2 and we haven't changed the height yet
                    // we must get from pre fork2 storage.
                    //
                    // We don't even check storage cache with pre fork2 keys here because
                    // if pre fork2 storage is read in Fork2,
                    // it would be written also be written to the cache with fork2 keys.
                    // And we wouldn't be here.

                    let pre_fork2_key = Evm::<C>::get_storage_key_pre_fork2(
                        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
                        &U256::ZERO,
                    );

                    bcs_deserialize_value(
                        storage
                            .get_and_prove(&pre_fork2_key, last_l1_hash_witness, final_state_root)
                            .expect("Should exist")
                            .into_cache_value()
                            .value,
                    )
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
    let last_l1_hash: U256 = match state_log.get_value(&key.clone().into_cache_key()) {
        ValueExists::Yes(value) => {
            borsh_deserialize_value(value.expect("L1 hash can't be None in cache").value)
        }
        ValueExists::No => {
            match storage.get_and_prove(&key, last_l1_hash_witness, final_state_root) {
                Some(value) => borsh_deserialize_value(value.into_cache_value().value),
                None => {
                    // If this is the first proof in Fork2 and we haven't changed the height yet
                    // we must get from pre fork2 storage.
                    //
                    // We don't even check storage cache with pre fork2 keys here because
                    // if pre fork2 storage is read in Fork2,
                    // it would be written also be written to the cache with fork2 keys.
                    // And we wouldn't be here.

                    let pre_fork2_key = Evm::<C>::get_storage_key_pre_fork2(
                        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
                        &evm_storage_slot,
                    );

                    bcs_deserialize_value(
                        storage
                            .get_and_prove(&pre_fork2_key, last_l1_hash_witness, final_state_root)
                            .expect("Should exist")
                            .into_cache_value()
                            .value,
                    )
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

fn bcs_deserialize_value<T>(bytes: RefCount<[u8]>) -> T
where
    BcsCodec: StateValueCodec<T>,
{
    (BcsCodec {}).decode_value_unwrap(&bytes)
}
