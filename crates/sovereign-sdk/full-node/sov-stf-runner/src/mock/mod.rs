use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::transaction::Transaction;
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{
    ApplySequencerCommitmentsOutput, SoftConfirmationResult, StateTransitionError,
    StateTransitionFunction,
};

/// A mock implementation of the [`StateTransitionFunction`]
#[derive(PartialEq, Debug, Clone, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct MockStf;

impl<Da: DaSpec> StateTransitionFunction<Da> for MockStf {
    type Transaction = Transaction<DefaultContext>;
    type StateRoot = [u8; 0];
    type GenesisParams = ();
    type PreState = ();
    type ChangeSet = ();
    type TxReceiptContents = ();
    type BatchReceiptContents = ();
    type Witness = ();

    // Perform one-time initialization for the genesis block.
    fn init_chain(
        &self,
        _base_state: Self::PreState,
        _params: Self::GenesisParams,
    ) -> ([u8; 0], ()) {
        ([], ())
    }

    fn apply_soft_confirmation(
        &mut self,
        _current_spec: SpecId,
        _sequencer_public_key: &[u8],
        _pre_state_root: &Self::StateRoot,
        _pre_state: Self::PreState,
        _state_witness: Self::Witness,
        _offchain_witness: Self::Witness,
        _slot_header: &<Da as DaSpec>::BlockHeader,
        _soft_confirmation: &mut sov_modules_api::SignedSoftConfirmation<Self::Transaction>,
    ) -> Result<
        SoftConfirmationResult<Self::StateRoot, Self::ChangeSet, Self::Witness>,
        StateTransitionError,
    > {
        todo!()
    }

    fn apply_soft_confirmations_from_sequencer_commitments(
        &mut self,
        _sequencer_public_key: &[u8],
        _sequencer_da_public_key: &[u8],
        _initial_state_root: &Self::StateRoot,
        _pre_state: Self::PreState,
        _da_data: Vec<<Da as DaSpec>::BlobTransaction>,
        _sequencer_commitments_range: (u32, u32),
        _witnesses: std::collections::VecDeque<Vec<(Self::Witness, Self::Witness)>>,
        _slot_headers: std::collections::VecDeque<Vec<<Da as DaSpec>::BlockHeader>>,
        _soft_confirmations: std::collections::VecDeque<
            Vec<sov_modules_api::SignedSoftConfirmation<Self::Transaction>>,
        >,
        _preproven_commitment_indicies: Vec<usize>,
    ) -> ApplySequencerCommitmentsOutput<Self::StateRoot> {
        todo!()
    }
}
