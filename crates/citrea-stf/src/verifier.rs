use citrea_evm::{keccak256, Evm, BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS, U256};
use short_header_proof_provider::{ZkShortHeaderProofProviderService, SHORT_HEADER_PROOF_PROVIDER};
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_api::fork::Fork;
use sov_modules_api::{Context, DaSpec};
use sov_modules_stf_blueprint::{ApplySequencerCommitmentsOutput, Runtime, StfBlueprint};
use sov_rollup_interface::zk::batch_proof::input::v3::BatchProofCircuitInputV3Part1;
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_state::codec::BorshCodec;
use sov_state::storage::{StateCodec, StateValueCodec, Storage, StorageKey, ValueExists};

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

        let all = SHORT_HEADER_PROOF_PROVIDER
            .get()
            .unwrap()
            .take_queried_hashes(0..=0);

        let last_l1_hash = if !all.is_empty() {
            *all.last().unwrap()
        } else {
            let cumulative_state_log = cumulative_state_log.unwrap();
            let prefix = {
                let temp_evm = Evm::<ZkDefaultContext>::default();
                temp_evm.storage.prefix().clone()
            };

            // key for light client contract next l1 height
            let inner_evm_key = Evm::<ZkDefaultContext>::get_storage_address(
                &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
                &U256::ZERO,
            );

            let key = StorageKey::new(&prefix, &inner_evm_key, &BorshCodec);

            // first we try to get next L1 height from cache, if it does not exist in cache
            // we need to provide proof with respect to the latest root
            let next_l1_height = match cumulative_state_log.get_value(&key.clone().into_cache_key())
            {
                ValueExists::Yes(cache_value) => {
                    cache_value
                        .expect("Next L1 height can't be None in cache")
                        .value
                }
                ValueExists::No => {
                    let next_l1_height = pre_state
                        .get_and_prove(&key, &mut data.last_hash_witness, final_state_root)
                        .expect("should exist");

                    next_l1_height.into_cache_value().value
                }
            };

            let b = BorshCodec {};
            let next_l1_height: U256 = b.value_codec().decode_value_unwrap(&next_l1_height);

            // we calculate the corresponding EVM storage slot the last L1 height's hash lives
            let mut bytes = [0u8; 64];
            bytes[0..32].copy_from_slice(&(next_l1_height - U256::from(1)).to_be_bytes::<32>());
            // counter intuitively the contract stores next block height (expected on setBlockInfo)x
            bytes[32..64].copy_from_slice(&U256::from(1).to_be_bytes::<32>());

            let inner_evm_key = Evm::<ZkDefaultContext>::get_storage_address(
                &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
                &keccak256(bytes).into(),
            );

            let key = StorageKey::new(&prefix, &inner_evm_key, &BorshCodec);

            // we look for the value inside cache
            // if in cache we don't need to do anything
            // if not in cache we need to provide proof with respect to the latest root
            let last_l1_hash = match cumulative_state_log.get_value(&key.clone().into_cache_key()) {
                ValueExists::Yes(value) => value.expect("L1 hash can't be None in cache").value,
                ValueExists::No => {
                    pre_state
                        .get_and_prove(&key, &mut data.last_hash_witness, final_state_root)
                        .expect("L1 hash can't be None in storage")
                        .into_cache_value()
                        .value
                }
            };

            let last_l1_hash: U256 = b.value_codec().decode_value_unwrap(&last_l1_hash);

            last_l1_hash.to_be_bytes()
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
