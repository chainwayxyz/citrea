use short_header_proof_provider::{ZkShortHeaderProofProviderService, SHORT_HEADER_PROOF_PROVIDER};
use sov_modules_api::fork::Fork;
use sov_modules_api::DaSpec;
use sov_rollup_interface::stf::{ApplySequencerCommitmentsOutput, StateTransitionFunction};
use sov_rollup_interface::zk::batch_proof::input::v3::BatchProofCircuitInputV3Part1;
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::ZkvmGuest;

/// Verifies a state transition
pub struct StateTransitionVerifier<ST, Da>
where
    Da: DaSpec,
    ST: StateTransitionFunction<Da>,
{
    app: ST,
    phantom: std::marker::PhantomData<Da>,
}

impl<Stf, Da> StateTransitionVerifier<Stf, Da>
where
    Da: DaSpec,
    Stf: StateTransitionFunction<Da>,
{
    /// Create a [`StateTransitionVerifier`]
    pub fn new(app: Stf) -> Self {
        Self {
            app,
            phantom: Default::default(),
        }
    }

    /// Verify the next block
    pub fn run_sequencer_commitments_in_da_slot(
        &mut self,
        guest: &impl ZkvmGuest,
        pre_state: Stf::PreState,
        sequencer_public_key: &[u8],
        sequencer_k256_public_key: &[u8],
        forks: &[Fork],
    ) -> BatchProofCircuitOutputV3 {
        println!("Running sequencer commitments in DA slot");

        let data: BatchProofCircuitInputV3Part1<Da> = guest.read_from_host();

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
        } = self
            .app
            .apply_soft_confirmations_from_sequencer_commitments(
                guest,
                sequencer_public_key,
                sequencer_k256_public_key,
                &data.initial_state_root,
                pre_state,
                data.sequencer_commitments,
                data.da_block_headers_of_soft_confirmations,
                forks,
            );

        println!("out of apply_soft_confirmations_from_sequencer_commitments");

        BatchProofCircuitOutputV3 {
            initial_state_root: data.initial_state_root,
            final_state_root,
            final_soft_confirmation_hash,
            state_diff,
            last_l2_height,
            sequencer_commitment_merkle_roots,
        }
    }
}
