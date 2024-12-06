use std::marker::PhantomData;

use sov_rollup_interface::da::{BlockHeaderTrait, DaNamespace, DaVerifier};
use sov_rollup_interface::stf::{ApplySequencerCommitmentsOutput, StateTransitionFunction};
use sov_rollup_interface::zk::{BatchProofCircuitInput, BatchProofCircuitOutput, Zkvm, ZkvmGuest};

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

        // the hash will be checked inside the stf
        // so we can early copy that and use in the output
        // since the run will fail if the hash is wrong
        let final_soft_confirmation_hash = data
            .soft_confirmations
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
                data.sequencer_public_key.as_ref(),
                data.sequencer_da_public_key.as_ref(),
                &data.initial_state_root,
                pre_state,
                data.da_data,
                data.sequencer_commitments_range,
                data.state_transition_witnesses,
                data.da_block_headers_of_soft_confirmations,
                data.soft_confirmations,
                data.preproven_commitments.clone(),
            );

        println!("out of apply_soft_confirmations_from_sequencer_commitments");

        let out: BatchProofCircuitOutput<Da::Spec, _> = BatchProofCircuitOutput {
            initial_state_root: data.initial_state_root,
            final_state_root,
            final_soft_confirmation_hash,
            state_diff,
            prev_soft_confirmation_hash: data.prev_soft_confirmation_hash,
            da_slot_hash: data.da_block_header_of_commitments.hash(),
            sequencer_public_key: data.sequencer_public_key,
            sequencer_da_public_key: data.sequencer_da_public_key,
            sequencer_commitments_range: data.sequencer_commitments_range,
            preproven_commitments: data.preproven_commitments,
            last_l2_height,
        };

        zkvm.commit(&out);
        Ok(())
    }
}
