use accessors::{
    BatchProofMethodIdAccessor, BlockHashAccessor, ChunkAccessor, SequencerCommitmentAccessor,
    VerifiedStateTransitionForSequencerCommitmentIndexAccessor,
};
use borsh::BorshDeserialize;
use initial_values::LCP_JMT_GENESIS_ROOT;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::{BlobReaderTrait, DaSpec, WorkingSet, Zkvm};
use sov_modules_core::{ReadWriteLog, Storage};
use sov_rollup_interface::da::{BatchProofMethodId, DaVerifier, DataOnDa};
use sov_rollup_interface::witness::Witness;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::{
    LightClientCircuitOutput, VerifiedStateTransitionForSequencerCommitmentIndex,
};
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;

/// Accessor (helpers) that are used inside the light client proof circuit.
/// To access certain information that was saved to its state at one point.
pub(crate) mod accessors;
/// Initial values that are used to initialize the light client proof circuit.
pub mod initial_values;

/// A macro for logging messages.
#[macro_use]
mod log;

// L2 activation height of the fork, and the batch proof method ID
type InitialBatchProofMethodIds = Vec<(u64, [u32; 8])>;

type CircuitError = &'static str;

#[derive(Debug)]
pub enum LightClientVerificationError<DaV: DaVerifier> {
    DaTxsCouldntBeVerified(DaV::Error),
    HeaderChainVerificationFailed(DaV::Error),
    InvalidPreviousLightClientProof,
}

pub struct RunL1BlockResult<S: Storage> {
    l2_state_root: [u8; 32],
    pub lcp_state_root: [u8; 32],
    last_l2_height: u64,
    pub witness: Witness,
    pub change_set: S,
    last_sequencer_commitment_index: u32,
}

pub struct LightClientProofCircuit<S: Storage, DS: DaSpec, Z: Zkvm> {
    phantom: core::marker::PhantomData<(S, DS, Z)>,
}

impl<S: Storage, DS: DaSpec, Z: Zkvm> LightClientProofCircuit<S, DS, Z> {
    pub fn new() -> Self {
        Self {
            phantom: core::marker::PhantomData,
        }
    }

    fn verify_batch_proof_seq_comm_relation(
        &self,
        batch_proof_output: &BatchProofCircuitOutput,
        working_set: &mut WorkingSet<S>,
    ) -> bool {
        match (
            batch_proof_output.previous_commitment_index(),
            batch_proof_output.previous_commitment_hash(),
        ) {
            (
                Some(previous_commitment_index),
                Some(batch_proof_output_previous_commitment_hash),
            ) => {
                let previous_commitment = match SequencerCommitmentAccessor::<S>::get(
                    previous_commitment_index,
                    working_set,
                ) {
                    Some(commitment) => commitment,
                    None => {
                        log!(
                            "Sequencer commitment with index {} does not exist in the jmt state",
                            previous_commitment_index
                        );
                        return false;
                    }
                };
                let previous_commitment_hash =
                    previous_commitment.serialize_and_calculate_sha_256();
                if previous_commitment_hash != batch_proof_output_previous_commitment_hash {
                    log!(
                        "Previous commitment hash mismatch, expected: {:?}, got: {:?}",
                        previous_commitment_hash,
                        batch_proof_output_previous_commitment_hash
                    );
                    return false;
                }
            }
            _ => {
                // If there are no previous commitments then this should be the first batch proof
                // The first batch proof's first commitment index should be 1
                if batch_proof_output.sequencer_commitment_index_range().0 != 1 {
                    log!(
                        "Previous commitment index is not set, but sequencer commitment index range start is not 1: {}",
                        batch_proof_output.sequencer_commitment_index_range().0
                    );
                    return false;
                }
            }
        }

        let (first_index, last_index) = batch_proof_output.sequencer_commitment_index_range();
        let batch_proof_output_sequencer_commitment_hashes =
            batch_proof_output.sequencer_commitment_hashes();

        // The index range len should be equal to the number of sequencer commitment hashes in the batch proof output
        if (last_index - first_index + 1) as usize
            != batch_proof_output_sequencer_commitment_hashes.len()
        {
            log!(
                "Sequencer commitment index range length mismatch, expected: {}, got: {}",
                (last_index - first_index + 1),
                batch_proof_output_sequencer_commitment_hashes.len()
            );
            return false;
        }

        for (i, (batch_proof_sequencer_commitment_index, batch_proof_sequencer_commitment_hash)) in
            (first_index..=last_index)
                .zip(batch_proof_output_sequencer_commitment_hashes)
                .enumerate()
        {
            let jmt_commitment = match SequencerCommitmentAccessor::<S>::get(
                batch_proof_sequencer_commitment_index,
                working_set,
            ) {
                Some(commitment) => commitment,
                None => {
                    log!(
                        "Sequencer commitment with index {} does not exist in the jmt state",
                        batch_proof_sequencer_commitment_index
                    );
                    return false;
                }
            };

            // If this is the last commitment check the l2 heights matching
            // This is unreachable, because if seq comm hashes are matching then the l2 heights must match
            // because we assert in batch proof
            if i as u32 == last_index - first_index
                && jmt_commitment.l2_end_block_number != batch_proof_output.last_l2_height()
            {
                log!(
                    "Last sequencer commitment l2 height mismatch, expected: {}, got: {}",
                    jmt_commitment.l2_end_block_number,
                    batch_proof_output.last_l2_height()
                );
                return false;
            }

            let jmt_commitment_hash = jmt_commitment.serialize_and_calculate_sha_256();
            if jmt_commitment_hash != batch_proof_sequencer_commitment_hash {
                log!(
                    "Sequencer commitment hash mismatch, expected: {:?}, got: {:?}",
                    jmt_commitment_hash,
                    batch_proof_sequencer_commitment_hash
                );
                return false;
            }
        }

        true
    }

    fn process_complete_proof(
        &self,
        proof: &[u8],
        last_l2_height: u64,
        last_sequencer_commitment_index: u32,
        working_set: &mut WorkingSet<S>,
    ) -> Result<(), CircuitError> {
        let Ok(journal) = Z::extract_raw_output(proof) else {
            return Err("Failed to extract output from proof");
        };

        let batch_proof_output = Z::deserialize_output::<BatchProofCircuitOutput>(&journal)
            .map_err(|_| "Failed to deserialize output")?;
        if !BlockHashAccessor::<S>::exists(
            batch_proof_output.last_l1_hash_on_bitcoin_light_client_contract(),
            working_set,
        ) {
            return Err("Batch proof with unknown header chain");
        }

        let batch_proof_output_state_roots = batch_proof_output.state_roots();
        let batch_proof_output_last_l2_height = batch_proof_output.last_l2_height();
        let batch_proof_output_sequencer_commitment_index_range =
            batch_proof_output.sequencer_commitment_index_range();
        let batch_proof_output_last_commitment_index =
            batch_proof_output_sequencer_commitment_index_range.1;

        // Do not add if last l2 height is smaller or equal to previous output
        // This is to defend against replay attacks, for example if somehow there is the script of batch proof 1 we do not need to go through it again
        if batch_proof_output_last_l2_height <= last_l2_height && last_l2_height != 0 {
            return Err("Last L2 height is less than proof's last l2 height");
        }

        let batch_proof_method_ids = BatchProofMethodIdAccessor::<S>::get(working_set)
            .expect("Batch proof method ids must exist");

        let batch_proof_method_id = if batch_proof_method_ids.len() == 1 {
            batch_proof_method_ids[0].1
        } else {
            let idx = match batch_proof_method_ids
                // Returns err and the index to be inserted, which is the index of the first element greater than the key
                // That is why we need to subtract 1 to get the last element smaller than the key
                .binary_search_by_key(&batch_proof_output_last_l2_height, |(height, _)| *height)
            {
                Ok(idx) => idx,
                Err(idx) => idx.saturating_sub(1),
            };
            batch_proof_method_ids[idx].1
        };

        log!("Using batch proof method id {:?}", batch_proof_method_id);

        Z::verify(proof, &batch_proof_method_id.into()).map_err(|_| "Failed to verify proof")?;

        if !self.verify_batch_proof_seq_comm_relation(&batch_proof_output, working_set) {
            return Err("Failed to verify sequencer commitment relation");
        }

        if batch_proof_output_last_commitment_index <= last_sequencer_commitment_index {
            return Err("Last commitment index is less than or equal to previous output");
        }

        for (idx, seq_comm_index) in (batch_proof_output.sequencer_commitment_index_range().0
            ..=batch_proof_output.sequencer_commitment_index_range().1)
            .enumerate()
        {
            // No need to add data to jmt if index is less than or equal to the current index, because it will be the same since they have the same seq comm hash
            // Also no need to add if we already have the same index.
            if seq_comm_index <= last_sequencer_commitment_index
                || VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<S>::get(
                    seq_comm_index,
                    working_set,
                )
                .is_some()
            {
                continue;
            }
            let jmt_commitment = SequencerCommitmentAccessor::<S>::get(seq_comm_index, working_set)
                .expect("Sequencer commitment must exist at this point");
            VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<S>::insert(
                seq_comm_index,
                VerifiedStateTransitionForSequencerCommitmentIndex::new(
                    batch_proof_output_state_roots[idx],
                    // No overflow because the length is sequencer commitments count + 1
                    batch_proof_output_state_roots[idx + 1],
                    jmt_commitment.l2_end_block_number,
                ),
                working_set,
            );
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    // will be called by the circuit and native
    pub fn run_l1_block(
        &self,
        storage: S,
        witness: Witness,
        da_txs: Vec<DS::BlobTransaction>,
        da_block_header: DS::BlockHeader,
        previous_light_client_proof_output: Option<LightClientCircuitOutput>,
        l2_genesis_root: [u8; 32],
        initial_batch_proof_method_ids: InitialBatchProofMethodIds,
        batch_prover_da_public_key: &[u8],
        sequencer_da_public_key: &[u8],
        method_id_upgrade_authority_da_public_key: &[u8],
    ) -> RunL1BlockResult<S> {
        let mut working_set =
            WorkingSet::with_witness(storage.clone(), witness, Default::default());

        // first insert the block hash into the JMT
        BlockHashAccessor::<S>::insert(da_block_header.hash().into(), &mut working_set);

        let (mut last_l2_state_root, mut last_l2_height, mut last_sequencer_commitment_index) =
            previous_light_client_proof_output.as_ref().map_or_else(
                || {
                    // if no previous proof, we start from genesis state root
                    (l2_genesis_root, 0, 0)
                },
                |prev_journal| {
                    (
                        prev_journal.l2_state_root,
                        prev_journal.last_l2_height,
                        prev_journal.last_sequencer_commitment_index,
                    )
                },
            );

        // If this is the first lcp initialize the batch proof method ids
        if previous_light_client_proof_output.is_none() {
            BatchProofMethodIdAccessor::<S>::initialize(
                initial_batch_proof_method_ids,
                &mut working_set,
            );
        }

        'blob_loop: for blob in da_txs {
            let Ok(data) = DataOnDa::try_from_slice(blob.full_data()) else {
                log!("Unparsable blob in da_data, wtxid={:?}", blob.wtxid());
                continue;
            };

            match data {
                // No need to check sender for chunk
                DataOnDa::Chunk(chunk) => {
                    log!("Found chunk");

                    ChunkAccessor::<S>::insert(
                        blob.wtxid().expect("Chunk should have wtxid"),
                        chunk,
                        &mut working_set,
                    );
                }
                DataOnDa::Complete(proof) => {
                    log!("Found complete proof");
                    if blob.sender().as_ref() != batch_prover_da_public_key {
                        log!(
                            "Complete proof sender is not batch prover, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }

                    match self.process_complete_proof(
                        &proof,
                        last_l2_height,
                        last_sequencer_commitment_index,
                        &mut working_set,
                    ) {
                        Ok(()) => {}
                        Err(e) => log!("Error processing complete proof: {e}"),
                    }
                }
                DataOnDa::Aggregate(_, wtxids) => {
                    log!("Found aggregate proof");
                    if blob.sender().as_ref() != batch_prover_da_public_key {
                        log!(
                            "Aggregate proof sender is not batch prover, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }

                    let mut complete_proof = Vec::new();

                    // Ensure that aggregate has all the needed chunks.
                    for wtxid in &wtxids {
                        match ChunkAccessor::<S>::get(*wtxid, &mut working_set) {
                            Some(body) => complete_proof.extend_from_slice(body.as_ref()),
                            None => {
                                log!(
                                    "Unknown chunk in aggregate proof, wtxid={:?} skipping",
                                    wtxid
                                );
                                continue 'blob_loop;
                            }
                        }
                    }

                    log!("Aggregate has all needed chunks!");

                    let Ok(complete_proof) = DS::decompress_chunks(&complete_proof) else {
                        log!("Failed to decompress and deserialize completed chunks");
                        continue;
                    };

                    match self.process_complete_proof(
                        &complete_proof,
                        last_l2_height,
                        last_sequencer_commitment_index,
                        &mut working_set,
                    ) {
                        Ok(()) => {}
                        // proof resulting from chunk concatanation is not valid
                        // either due to ZK proof being invalid
                        // a deserialization error
                        // or the resulting output was ZK-valid but included an L1 hash
                        // that was not know to the prover
                        Err(e) => {
                            log!("Error processing aggregated proof: {e}");
                        }
                    }
                }
                DataOnDa::BatchProofMethodId(BatchProofMethodId {
                    method_id,
                    activation_l2_height,
                }) => {
                    log!("Found batch proof method id");
                    if blob.sender().as_ref() != method_id_upgrade_authority_da_public_key {
                        log!(
                            "Batch proof method id sender is not upgrade authority, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }

                    let batch_proof_method_ids =
                        BatchProofMethodIdAccessor::<S>::get(&mut working_set).unwrap();

                    let last_activation_height = batch_proof_method_ids
                        .last()
                        .expect("Should be at least one")
                        .0;

                    if activation_l2_height > last_activation_height {
                        BatchProofMethodIdAccessor::<S>::insert(
                            activation_l2_height,
                            method_id,
                            &mut working_set,
                        );
                    }
                }
                DataOnDa::SequencerCommitment(commitment) => {
                    log!("Found sequencer commitment with index {}", commitment.index);
                    if blob.sender().as_ref() != sequencer_da_public_key {
                        log!(
                            "Sequencer commitment sender is not sequencer, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }
                    if SequencerCommitmentAccessor::<S>::get(commitment.index, &mut working_set)
                        .is_none()
                    {
                        SequencerCommitmentAccessor::<S>::insert(
                            commitment.index,
                            commitment,
                            &mut working_set,
                        )
                    }
                }
            }
        }

        // Try to chain proofs using commitments
        // With this setup even if we have valid proofs with commitments like 3,4,5 and 5,6
        // We can update our last commitment index to 6
        while let Some(sequencer_commitment_info) =
            VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<S>::get(
                last_sequencer_commitment_index + 1,
                &mut working_set,
            )
        {
            if sequencer_commitment_info.initial_state_root == last_l2_state_root {
                last_l2_state_root = sequencer_commitment_info.final_state_root;
                last_l2_height = sequencer_commitment_info.last_l2_height;
                last_sequencer_commitment_index += 1;
            } else {
                // This should be infallible
                // this can only happen if commitment started committing to a different chain
                unreachable!("Commitment with the next index having an unexpected state root");
            }
        }

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        // https://github.com/chainwayxyz/citrea/issues/2046
        // which we don't need in this circuit
        // maybe create new function or pass argument for state diff building
        let (lcp_state_root_transition, jmt_state_update, _) = storage
            .compute_state_update(&read_write_log, &mut witness, false)
            .expect("jellyfish merkle tree update must succeed");

        if let Some(output) = previous_light_client_proof_output {
            // If we had a previous light client proof, make sure the prev_root used in the JMT update proof
            // was the same as the previous light client proof's
            assert_eq!(
                lcp_state_root_transition.init_root, output.lcp_state_root,
                "Witness prev root is wrong!"
            );
        } else {
            // if running for the first time, we are going to be initializing the JMT
            // so the genesis root must this constant
            assert_eq!(lcp_state_root_transition.init_root, LCP_JMT_GENESIS_ROOT);
        }

        storage.commit(&jmt_state_update, &vec![], &ReadWriteLog::default());

        RunL1BlockResult {
            l2_state_root: last_l2_state_root,
            lcp_state_root: lcp_state_root_transition.final_root,
            last_l2_height,
            witness,
            change_set: storage,
            last_sequencer_commitment_index,
        }
    }

    #[allow(clippy::too_many_arguments)]
    // will only called by the circuit
    pub fn run_circuit<DaV>(
        &self,
        da_verifier: DaV,
        input: LightClientCircuitInput<DaV::Spec>,
        storage: S,
        network: Network,
        l2_genesis_root: [u8; 32],
        initial_batch_proof_method_ids: InitialBatchProofMethodIds,
        batch_prover_da_public_key: &[u8],
        sequencer_da_public_key: &[u8],
        method_id_upgrade_authority_da_public_key: &[u8],
    ) -> Result<LightClientCircuitOutput, LightClientVerificationError<DaV>>
    where
        DaV: DaVerifier<Spec = DS>,
        Z: ZkvmGuest,
    {
        // from input, parse previous light client proof output
        let previous_light_client_proof_output =
            if let Some(proof) = input.previous_light_client_proof {
                // previous LCP is verified with the host verify API
                let prev_output = Z::verify_and_deserialize_output::<LightClientCircuitOutput>(
                    &proof,
                    &input.light_client_proof_method_id.into(),
                )
                .expect("Previous light client proof is invalid");

                // Ensure method IDs match
                assert_eq!(
                    input.light_client_proof_method_id,
                    prev_output.light_client_proof_method_id,
                );
                Some(prev_output)
            } else {
                None
            };

        let new_da_state = da_verifier
            .verify_header_chain(
                previous_light_client_proof_output
                    .as_ref()
                    .map(|output| &output.latest_da_state),
                &input.da_block_header,
                network,
            )
            .map_err(|err| LightClientVerificationError::HeaderChainVerificationFailed(err))?;

        // extract DA transactions from the block
        let da_txs = da_verifier
            .verify_transactions(
                &input.da_block_header,
                input.inclusion_proof,
                input.completeness_proof,
            )
            .map_err(|err| LightClientVerificationError::DaTxsCouldntBeVerified(err))?;

        // then we can call run_l1_block to run the logic of the circuit
        let result = self.run_l1_block(
            storage,
            input.witness,
            da_txs,
            input.da_block_header,
            previous_light_client_proof_output,
            l2_genesis_root,
            initial_batch_proof_method_ids,
            batch_prover_da_public_key,
            sequencer_da_public_key,
            method_id_upgrade_authority_da_public_key,
        );

        Ok(LightClientCircuitOutput {
            l2_state_root: result.l2_state_root,
            light_client_proof_method_id: input.light_client_proof_method_id,
            latest_da_state: new_da_state,
            last_l2_height: result.last_l2_height,
            lcp_state_root: result.lcp_state_root,
            last_sequencer_commitment_index: result.last_sequencer_commitment_index,
        })
    }
}

impl<S: Storage, DS: DaSpec, Z: Zkvm> Default for LightClientProofCircuit<S, DS, Z> {
    fn default() -> Self {
        Self::new()
    }
}
