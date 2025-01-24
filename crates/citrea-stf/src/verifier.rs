use sov_modules_api::fork::Fork;
use sov_rollup_interface::da::{BlockHeaderTrait, DaNamespace, DaVerifier};
use sov_rollup_interface::stf::{ApplySequencerCommitmentsOutput, StateTransitionFunction};
use sov_rollup_interface::zk::{BatchProofCircuitInputV2Part1, BatchProofCircuitOutput, ZkvmGuest};

/// Verifies a state transition
pub struct StateTransitionVerifier<ST, Da>
where
    Da: DaVerifier,
    ST: StateTransitionFunction<Da::Spec>,
{
    app: ST,
    da_verifier: Da,
}

impl<Stf, Da> StateTransitionVerifier<Stf, Da>
where
    Da: DaVerifier,
    Stf: StateTransitionFunction<Da::Spec>,
{
    /// Create a [`StateTransitionVerifier`]
    pub fn new(app: Stf, da_verifier: Da) -> Self {
        Self { app, da_verifier }
    }

    /// Verify the next block
    pub fn run_sequencer_commitments_in_da_slot(
        &mut self,
        guest: &impl ZkvmGuest,
        pre_state: Stf::PreState,
        sequencer_public_key: &[u8],
        sequencer_da_public_key: &[u8],
        forks: &[Fork],
    ) -> Result<BatchProofCircuitOutput<Da::Spec, Stf::StateRoot>, Da::Error> {
        println!("Running sequencer commitments in DA slot");

        let data: BatchProofCircuitInputV2Part1<Stf::StateRoot, Da::Spec> = guest.read_from_host();

        if !data.da_block_header_of_commitments.verify_hash() {
            panic!("Invalid hash of DA block header of commitments");
        }

        self.da_verifier.verify_transactions(
            &data.da_block_header_of_commitments,
            &data.da_data,
            data.inclusion_proof,
            data.completeness_proof,
            DaNamespace::ToBatchProver,
        )?;

        println!("going into apply_soft_confirmations_from_sequencer_commitments");
        let ApplySequencerCommitmentsOutput {
            final_state_root,
            state_diff,
            last_l2_height,
            final_soft_confirmation_hash,
        } = self
            .app
            .apply_soft_confirmations_from_sequencer_commitments(
                guest,
                sequencer_public_key,
                sequencer_da_public_key,
                &data.initial_state_root,
                pre_state,
                data.da_data,
                data.sequencer_commitments_range,
                data.da_block_headers_of_soft_confirmations,
                data.preproven_commitments.clone(),
                forks,
            );

        println!("out of apply_soft_confirmations_from_sequencer_commitments");

        let out = BatchProofCircuitOutput {
            initial_state_root: data.initial_state_root,
            final_state_root,
            final_soft_confirmation_hash,
            state_diff,
            prev_soft_confirmation_hash: data.prev_soft_confirmation_hash,
            da_slot_hash: data.da_block_header_of_commitments.hash(),
            sequencer_public_key: sequencer_public_key.to_vec(),
            sequencer_da_public_key: sequencer_da_public_key.to_vec(),
            sequencer_commitments_range: data.sequencer_commitments_range,
            preproven_commitments: data.preproven_commitments,
            last_l2_height,
        };

        Ok(out)
    }
}
