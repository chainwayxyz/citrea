use std::marker::PhantomData;

use sov_rollup_interface::da::{BlockHeaderTrait, DaNamespace, DaVerifier};
use sov_rollup_interface::stf::{ApplySequencerCommitmentsOutput, StateTransitionFunction};
use sov_rollup_interface::zk::{
    BatchProofCircuitInput, BatchProofCircuitOutput, BatchProofCircuitOutputV1,
    BatchProofCircuitOutputV2, Zkvm, ZkvmGuest,
};

/// Verifies a state transition
pub struct StateTransitionVerifier<ST, Da, Zk>
where
    Da: DaVerifier,
    Zk: Zkvm,
    ST: StateTransitionFunction<Da::Spec>,
{
    app: ST,
    da_verifier: Da,
    phantom: PhantomData<Zk>,
}

impl<Stf, Da, Zk> StateTransitionVerifier<Stf, Da, Zk>
where
    Da: DaVerifier,
    Zk: ZkvmGuest,
    Stf: StateTransitionFunction<Da::Spec>,
{
    /// Create a [`StateTransitionVerifier`]
    pub fn new(app: Stf, da_verifier: Da) -> Self {
        Self {
            app,
            da_verifier,
            phantom: Default::default(),
        }
    }

    /// Verify the next block
    pub fn run_sequencer_commitments_in_da_slot(
        &mut self,
        zkvm: Zk,
        pre_state: Stf::PreState,
    ) -> Result<(), Da::Error> {
        println!("Running sequencer commitments in DA slot");
        let data: BatchProofCircuitInput<Stf::StateRoot, _, Da::Spec, Stf::Transaction> =
            zkvm.read_from_host();

        let (
            version,
            da_block_header_of_commitments,
            da_block_headers_of_soft_confirmations,
            da_data,
            inclusion_proof,
            completeness_proof,
            sequencer_da_public_key,
            sequencer_public_key,
            initial_state_root,
            prev_soft_confirmation_hash,
            sequencer_commitments_range,
            state_transition_witnesses,
            soft_confirmations,
            preproven_commitments,
        ) = match data {
            BatchProofCircuitInput::V1(input) => (
                1,
                input.da_block_header_of_commitments,
                input.da_block_headers_of_soft_confirmations,
                input.da_data,
                input.inclusion_proof,
                input.completeness_proof,
                input.sequencer_da_public_key,
                input.sequencer_public_key,
                input.initial_state_root,
                Some(input.prev_soft_confirmation_hash),
                input.sequencer_commitments_range,
                input.state_transition_witnesses,
                input.soft_confirmations,
                input.preproven_commitments,
            ),
            BatchProofCircuitInput::V2(input) => (
                2,
                input.da_block_header_of_commitments,
                input.da_block_headers_of_soft_confirmations,
                input.da_data,
                input.inclusion_proof,
                input.completeness_proof,
                input.sequencer_da_public_key,
                input.sequencer_public_key,
                input.initial_state_root,
                None,
                input.sequencer_commitments_range,
                input.state_transition_witnesses,
                input.soft_confirmations,
                input.preproven_commitments,
            ),
        };

        if !da_block_header_of_commitments.verify_hash() {
            panic!("Invalid hash of DA block header of commitments");
        }

        self.da_verifier.verify_transactions(
            &da_block_header_of_commitments,
            &da_data,
            inclusion_proof,
            completeness_proof,
            DaNamespace::ToBatchProver,
        )?;

        // the hash will be checked inside the stf
        // so we can early copy that and use in the output
        // since the run will fail if the hash is wrong
        let final_soft_confirmation_hash = soft_confirmations
            .iter()
            .last()
            .expect("Should have at least one sequencer commitment")
            .iter()
            .last()
            .expect("Should have at least one soft confirmation")
            .hash();

        println!("going into apply_soft_confirmations_from_sequencer_commitments");
        let ApplySequencerCommitmentsOutput {
            final_state_root,
            state_diff,
            last_l2_height,
        } = self
            .app
            .apply_soft_confirmations_from_sequencer_commitments(
                sequencer_public_key.as_ref(),
                sequencer_da_public_key.as_ref(),
                &initial_state_root,
                pre_state,
                da_data,
                sequencer_commitments_range,
                state_transition_witnesses,
                da_block_headers_of_soft_confirmations,
                soft_confirmations,
                preproven_commitments.clone(),
            );

        println!("out of apply_soft_confirmations_from_sequencer_commitments");

        let out: BatchProofCircuitOutput<Da::Spec, _> = if version == 1 {
            BatchProofCircuitOutput::V1(BatchProofCircuitOutputV1 {
                initial_state_root,
                final_state_root,
                prev_soft_confirmation_hash: prev_soft_confirmation_hash
                    .expect("prev_soft_confirmation_hash not set for V1 input"),
                final_soft_confirmation_hash,
                state_diff,
                da_slot_hash: da_block_header_of_commitments.hash(),
                sequencer_commitments_range,
                sequencer_public_key,
                sequencer_da_public_key,
                preproven_commitments,
                last_l2_height,
            })
        } else {
            BatchProofCircuitOutput::V2(BatchProofCircuitOutputV2 {
                initial_state_root,
                final_state_root,
                final_soft_confirmation_hash,
                state_diff,
                da_slot_hash: da_block_header_of_commitments.hash(),
                sequencer_public_key,
                sequencer_da_public_key,
                sequencer_commitments_range,
                preproven_commitments,
                last_l2_height,
            })
        };

        zkvm.commit(&out);
        Ok(())
    }
}
