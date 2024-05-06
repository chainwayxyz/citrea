use std::marker::PhantomData;

use borsh::BorshDeserialize;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{BlockHeaderTrait, DaData, DaVerifier, SequencerCommitment};
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::{StateTransition, StateTransitionData, Zkvm, ZkvmGuest};

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
    pub fn run_block(&self, zkvm: Zk, pre_state: Stf::PreState) -> Result<(), Da::Error> {
        let mut data: StateTransitionData<Stf::StateRoot, _, Da::Spec> = zkvm.read_from_host();
        let validity_condition = self.da_verifier.verify_relevant_tx_list(
            &data.da_block_header_of_commitments,
            &data.da_data,
            data.inclusion_proof,
            data.completeness_proof,
        )?;

        // First extract all sequencer commitments
        // Ignore broken DaData and zk proofs. Also ignore ForcedTransaction's (will be implemented in the future).
        let mut sequencer_commitments: Vec<SequencerCommitment> = vec![];
        for blob in data.da_data.iter() {
            // TODO: get sequencer da pub key
            if blob.sender().as_ref() == &[0; 32] {
                let da_data = DaData::try_from_slice(blob.full_data());

                match da_data {
                    Ok(DaData::SequencerCommitment(commitment)) => {
                        sequencer_commitments.push(commitment);
                    }
                    _ => {}
                }
            }
        }

        // Then verify these soft confirmations.

        let mut current_state_root = data.initial_state_root.clone();

        for sequencer_commitment in sequencer_commitments.iter() {
            // should panic if number of sequencer commitments and soft confirmations don't match
            let mut soft_confirmations = data.soft_confirmations.pop_front().unwrap();

            // should panic if number of sequencer commitments and set of DA block headers don't match
            let da_block_headers = data
                .da_block_headers_of_soft_confirmations
                .pop_front()
                .unwrap();

            // should panic if number of sequencer commitments and set of witnesses don't match
            let witnesses = data.state_transition_witnesses.pop_front().unwrap();

            // we must verify given DA headers match the commitments
            let mut index_headers = 0;
            let mut index_soft_confirmation = 0;
            let mut soft_confirmation_starting_da_slot_height =
                soft_confirmations[index_soft_confirmation].da_slot_height();
            let mut current_da_height = da_block_headers[index_headers].height();

            assert_eq!(
                soft_confirmations[index_soft_confirmation].da_slot_hash(),
                da_block_headers[index_headers].hash().into()
            );

            assert_eq!(
                soft_confirmations[index_soft_confirmation].da_slot_height(),
                da_block_headers[index_headers].height()
            );

            index_soft_confirmation += 1;

            // TODO: chech for no da block height jump
            while index_soft_confirmation < soft_confirmations.len() {
                // the soft confirmations DA hash mus equal to da hash in index_headers
                // if it's not matching, and if it's not matching the next one, then stat transition is invalid.

                if soft_confirmations[index_soft_confirmation].hash()
                    == da_block_headers[index_headers].hash().into()
                {
                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].da_slot_height(),
                        da_block_headers[index_headers].height()
                    );

                    index_soft_confirmation += 1;
                } else {
                    index_headers += 1;

                    // this can also be done in soft confirmation rule enforcer?
                    assert_eq!(
                        da_block_headers[index_headers].height(),
                        current_da_height + 1
                    );

                    current_da_height += 1;

                    // if the next one is not matching, then the state transition is invalid.
                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].da_slot_hash(),
                        da_block_headers[index_headers].hash().into()
                    );

                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].da_slot_height(),
                        da_block_headers[index_headers].height()
                    );

                    index_soft_confirmation += 1;
                }
            }

            // final da header was checked against
            assert_eq!(index_headers, da_block_headers.len() - 1);

            // now verify the claimed merkle root of soft confirmation hashes
            let mut soft_confirmation_hashes = vec![];

            for soft_confirmation in soft_confirmations.iter() {
                // given hashes will be checked inside apply_soft_confirmation.
                // so use the claimed hash for now.
                soft_confirmation_hashes.push(soft_confirmation.hash());
            }

            let calculated_root =
                MerkleTree::<Sha256>::from_leaves(soft_confirmation_hashes.as_slice()).root();

            assert_eq!(calculated_root, Some(sequencer_commitment.merkle_root));

            let mut witness_iter = witnesses.into_iter();
            let mut da_block_headers_iter = da_block_headers.into_iter().peekable();
            let mut da_block_header = da_block_headers_iter.next().unwrap();
            // now that we verified the claimed root, we can apply the soft confirmations
            for soft_confirmation in soft_confirmations.iter_mut() {
                if soft_confirmation.da_slot_height()
                    != da_block_headers_iter.peek().unwrap().height()
                {
                    da_block_header = da_block_headers_iter.next().unwrap();
                }

                let result = self.app.apply_soft_batch(
                    &[0; 32],
                    &current_state_root,
                    // TODO: either somehow commit to the prestate after each soft confirmation and pass the correct prestate here, or run every soft confirmation all at once.
                    pre_state,
                    witness_iter.next().unwrap(), // should panic if the number of witnesses and soft confirmations don't match
                    &da_block_header,
                    &validity_condition,
                    soft_confirmation,
                );

                current_state_root = result.state_root;
            }
        }

        // let result = self.app.apply_slot(
        //     &data.initial_state_root,
        //     pre_state,
        //     data.state_transition_witness,
        //     &data.da_block_header,
        //     &validity_condition,
        //     &mut data.blobs,
        // );

        let out: StateTransition<Da::Spec, _> = StateTransition {
            initial_state_root: data.initial_state_root,
            final_state_root: current_state_root,
            validity_condition, // TODO: not sure about how to do this yet
            state_diff: vec![], // TODO: implement
        };

        zkvm.commit(&out);
        Ok(())
    }
}
