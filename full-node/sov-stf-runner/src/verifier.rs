use std::marker::PhantomData;

use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::{Zkvm, ZkvmGuest};

use crate::StateTransitionData;

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
    pub fn run_block(
        &self,
        zkvm: Zk,
        pre_state: Stf::PreState,
    ) -> Result<Stf::StateRoot, Da::Error> {
        let mut data: StateTransitionData<_, _, Da::Spec> = zkvm.read_from_host();
        let validity_condition = self.da_verifier.verify_relevant_tx_list(
            &data.da_block_header,
            &data.blobs,
            data.inclusion_proof,
            data.completeness_proof,
        )?;

        let result = self.app.apply_slot(
            &data.pre_state_root,
            pre_state,
            data.state_transition_witness,
            &data.da_block_header,
            &validity_condition,
            &mut data.blobs,
        );

        zkvm.commit(&result.state_root);
        Ok(result.state_root)
    }
}
