use std::marker::PhantomData;

use sov_rollup_interface::da::{BlockHeaderTrait, DaVerifier};
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::{
    CumulativeStateDiff, StateTransition, StateTransitionData, Zkvm, ZkvmGuest,
};

/// Verifies a state transition
pub struct StateTransitionVerifier<ST, Da, Zk>
where
    Da: DaVerifier,
    Zk: Zkvm,
    ST: StateTransitionFunction<Zk, Da::Spec>,
{
    app: ST,
    da_verifier: Da,
    phantom: PhantomData<Zk>,
}

impl<Stf, Da, Zk> StateTransitionVerifier<Stf, Da, Zk>
where
    Da: DaVerifier,
    Zk: ZkvmGuest,
    Stf: StateTransitionFunction<Zk, Da::Spec>,
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
        &self,
        zkvm: Zk,
        pre_state: Stf::PreState,
    ) -> Result<(), Da::Error> {
        let data: StateTransitionData<Stf::StateRoot, _, Da::Spec> = zkvm.read_from_host();
        let validity_condition = self.da_verifier.verify_relevant_tx_list(
            &data.da_block_header_of_commitments,
            &data.da_data,
            data.inclusion_proof,
            data.completeness_proof,
        )?;

        // tracing::info!("going into apply_soft_confirmations_from_sequencer_commitments");
        let (final_state_root, state_diff) = self
            .app
            .apply_soft_confirmations_from_sequencer_commitments(
                data.sequencer_public_key.as_ref(),
                data.sequencer_da_public_key.as_ref(),
                &data.initial_state_root,
                pre_state,
                data.da_data,
                data.state_transition_witnesses,
                data.da_block_headers_of_soft_confirmations,
                &validity_condition,
                data.soft_confirmations,
            );

        assert_eq!(
            final_state_root.as_ref(),
            data.final_state_root.as_ref(),
            "Invalid final state root"
        );

        // Collect state diffs into a BtreeMap
        let state_diff: CumulativeStateDiff = state_diff
            .into_iter()
            // .map(|(k, v)| (k, v))
            .collect();

        let out: StateTransition<Da::Spec, _> = StateTransition {
            initial_state_root: data.initial_state_root,
            final_state_root,
            validity_condition, // TODO: not sure about what to do with this yet
            state_diff,
            da_slot_hash: data.da_block_header_of_commitments.hash(),
            sequencer_public_key: data.sequencer_public_key,
            sequencer_da_public_key: data.sequencer_da_public_key,
        };

        zkvm.commit(&out);
        Ok(())
    }
}
