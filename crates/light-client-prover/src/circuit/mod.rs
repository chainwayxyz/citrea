//! # Light Client Circuit Module
//!
//! This module defines the logic of the light client circuit.
//! The light client circuit processes DA blocks, validates batch proofs, and generates proofs
//! that verify L2 state transitions and updates to the light client state.
use accessors::{
    BatchProofMethodIdAccessor, BatchProverDaPubKeyAccessor, BlockHashAccessor, ChunkAccessor,
    RevertEpochAccessor, SecurityCouncilAddressAccessor, SecurityCouncilNonceAccessor,
    SecurityCouncilThresholdAccessor, SequencerCommitmentAccessor,
    SequencerCommitmentEpochAccessor, SequencerDaPubKeyAccessor,
    VerifiedStateTransitionEpochAccessor,
    VerifiedStateTransitionForSequencerCommitmentIndexAccessor,
};
use alloy_primitives::Address;
use borsh::BorshDeserialize;
use citrea_primitives::{network_to_dev_mode, MAX_COMPRESSED_BLOB_SIZE};
use initial_values::LCP_JMT_GENESIS_ROOT;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::{BlobReaderTrait, DaSpec, WorkingSet, Zkvm};
use sov_modules_core::{ReadWriteLog, Storage};
use sov_rollup_interface::da::{
    DaVerifier, DataOnDa, SecurityCouncilTx, SecurityCouncilTxType, SetLcpToPreviousStateV1Body,
    MAX_NUMBER_OF_MEMBERS_IN_SECURITY_COUNCIL, MAX_THRESHOLD_PROXIMITY,
    MIN_NUMBER_OF_MEMBERS_IN_SECURITY_COUNCIL, MIN_THRESHOLD,
};
use sov_rollup_interface::witness::Witness;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::{
    LightClientCircuitOutput, VerifiedStateTransitionForSequencerCommitmentIndex,
};
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;

use crate::circuit::method_id_verifier::verify_security_council_signatures;

/// Accessor (helpers) that are used inside the light client proof circuit.
/// To access certain information that was saved to its state at one point.
pub(crate) mod accessors;
/// Initial values that are used to initialize the light client proof circuit.
pub mod initial_values;

/// A macro for logging messages.
#[macro_use]
mod log;

/// Verifies method id security council signatures.
mod method_id_verifier;

/// Security council messages that can be sent through the DA and processed by the light client proof circuit to update the circuit's configuration and security council members.
mod security_council;
pub use security_council::*;

/// L2 activation height of the fork, and the batch proof method ID
type InitialBatchProofMethodIds = Vec<(u64, [u32; 8])>;

/// Error type for the circuit
type CircuitError = &'static str;

#[derive(Debug)]
/// Error type for light client verification
pub enum LightClientVerificationError<DaV: DaVerifier> {
    /// The inclusion and completeness proofs could not be validated against the block header
    DaTxsCouldntBeVerified(DaV::Error),
    /// The block header is not valid under the Bitcoin consensus rules
    HeaderChainVerificationFailed(DaV::Error),
    /// The previous light client proof output is invalid
    InvalidPreviousLightClientProof,
}

/// Holds the result of processing the L1 block in the light client proof circuit.
pub struct RunL1BlockResult<S: Storage> {
    /// The verified L2 state root after processing the L1 block
    pub l2_state_root: [u8; 32],
    /// The JMT state root after processing the L1 block
    pub lcp_state_root: [u8; 32],
    /// The last verified L2 height after processing the L1 block
    pub last_l2_height: u64,
    /// Witness accumulates hints during the native execution. Hints are consumed by the circuit and allow access to the JMT state.
    pub witness: Witness,
    /// The change set that contains the JMT state updates and is used to finalize the JMT state after processing the L1 block.
    pub change_set: S,
    /// The verified last sequencer commitment index after processing the L1 block
    pub last_sequencer_commitment_index: u32,
}

/// LightClientProofCircuit struct implements the functionality of the light client proof circuit.
/// Contains methods that define the logic of the circuit, and holds the types of the storage, DA spec, and zkVM.
///
/// # Type Parameters
/// * `S` - Storage type implementing the Storage trait
/// * `DS` - Data Availability specification type implementing the DaSpec trait
/// * `Z` - ZKVM implementation type to verify the proofs and deserialize the outputs
pub struct LightClientProofCircuit<S: Storage, DS: DaSpec, Z: Zkvm> {
    /// Phantom data to hold the types of the storage, DA spec, and zkVM
    phantom: core::marker::PhantomData<(S, DS, Z)>,
}

impl<S: Storage, DS: DaSpec, Z: Zkvm> LightClientProofCircuit<S, DS, Z> {
    /// Creates a new instance of the LightClientProofCircuit.
    pub fn new() -> Self {
        Self {
            phantom: core::marker::PhantomData,
        }
    }

    /// Verifies that all the sequencer commitments in the batch proof output, including the previous commitment,
    /// match the sequencer commitments stored in the JMT state.
    ///
    /// # Arguments
    /// * `batch_proof_output` - The output of the batch proof circuit.
    /// * `working_set` - The working set to use accessors that read the JMT state.
    ///
    ///
    /// # Logic
    /// - If the batch proof output contains a previous commitment index and hash, compares it with the sequencer commitment stored in the JMT state.
    ///     If the previous commitment index is not set, ensures that the first commitment index in the batch proof output is 1.
    /// - For each sequencer commitment in the batch proof output, checks that the index and hash match the sequencer commitments stored in the JMT state.
    /// - Checks that if the last L2 height of last commitment matches the last L2 height in the batch proof output.
    ///
    /// # Returns
    /// * `true` if all checks are successful, `false` otherwise.
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

    /// Processes a complete proof, verifying it and validating it according to the current state of the JMT.
    /// If the proof is valid, all of the sequencer commitments in the proof's range are added to the JMT state as verified state transitions.
    ///
    /// # Arguments
    /// * `proof` - The serialized complete proof to process.
    /// * `last_l2_height` - The last L2 height known before processing this proof.
    /// * `last_sequencer_commitment_index` - The last sequencer commitment index known before processing this proof.
    /// * `network` - The Citrea network this light client proof is running on.
    /// * `working_set` - The working set to use accessor that reads the JMT state.
    ///
    /// # Logic
    ///
    /// - The proof is deserialized and the output is extracted.
    /// - The output is checked to ensure it contains a valid L1 hash that is known
    /// - The last L2 height of the output is checked to ensure it is greater than the last known height.
    /// - The batch proof method ID is read from the JMT based on the last L2 height.
    /// - The proof is verified using the batch proof method ID.
    /// - The sequencer commitment relation is verified to ensure the proof's sequencer commitments are known.
    /// - The last sequencer commitment index is checked to ensure it is greater than the last known index.
    ///
    /// At this point, the proof is considered valid and the sequencer commitments in the proof's range are added to the JMT state as verified state transitions.
    ///
    /// # Returns
    /// * `Ok(())` if the proof was processed successfully.
    /// * `Err(CircuitError)` if there was an error processing the proof, such as verification failure, deserialization error, or state root mismatch.
    fn process_complete_proof(
        &self,
        proof: &[u8],
        last_l2_height: u64,
        last_sequencer_commitment_index: u32,
        network: Network,
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

        Z::verify(
            proof,
            &batch_proof_method_id.into(),
            network_to_dev_mode(network),
        )
        .map_err(|_| "Failed to verify proof")?;

        if !self.verify_batch_proof_seq_comm_relation(&batch_proof_output, working_set) {
            return Err("Failed to verify sequencer commitment relation");
        }

        if batch_proof_output_last_commitment_index <= last_sequencer_commitment_index {
            return Err("Last commitment index is less than or equal to previous output");
        }

        let current_epoch = RevertEpochAccessor::<S>::get_or_default(working_set);

        for (idx, seq_comm_index) in (batch_proof_output.sequencer_commitment_index_range().0
            ..=batch_proof_output.sequencer_commitment_index_range().1)
            .enumerate()
        {
            // No need to add data to jmt if index is less than or equal to the current index
            if seq_comm_index <= last_sequencer_commitment_index {
                continue;
            }
            // Skip if already verified in the current epoch
            if VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<S>::get(
                seq_comm_index,
                working_set,
            )
            .is_some()
                && VerifiedStateTransitionEpochAccessor::<S>::get_or_default(
                    seq_comm_index,
                    working_set,
                ) == current_epoch
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
            VerifiedStateTransitionEpochAccessor::<S>::set(
                seq_comm_index,
                current_epoch,
                working_set,
            );
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    /// Called by both the native execution and the circuit.
    /// This function processes the relevant transactions, moves the L2 state forward, and validates the changes to the LCP’s JMT state.
    ///
    /// # Arguments
    /// * `network` - The Citrea network this light client proof is running on.
    /// * `storage` - The storage used for accessing the JMT state, performing updates, and validating read and write operations.
    /// * `witness` - The witness that contains the hints for the JMT state.
    /// * `da_txs` - Vector of the relevant transactions. Transactions are considered relevant if their wtxid begins with a predefined constant reveal transaction prefix.
    /// * `da_block_header` - The block header of the DA block that is being processed.
    /// * `previous_light_client_proof_output` - The previous light client proof output.
    /// * `l2_genesis_root` - The L2 genesis root, which is used to initialize the L2 state root if there is no previous light client proof output.
    /// * `initial_batch_proof_method_ids` - The initial batch proof method IDs that are used to initialize the batch proof method IDs in the JMT state if this is the first light client proof output.
    /// * `initial_batch_prover_da_public_key` - The initial public key of the batch prover, used to initialize the LCP state on first run.
    /// * `initial_sequencer_da_public_key` - The initial public key of the sequencer, used to initialize the LCP state on first run.
    /// * `initial_security_council_da_addresses` - The initial addresses of the security council, used to initialize the LCP state on first run.
    ///
    /// # Logic
    /// - The block hash of the header is inserted into the JMT.
    /// - The last sequencer commitment index, last L2 height, and L2 state root are retrieved from the previous light client proof.
    /// - If no previous proof exists, (0, 0, genesis root) is used as the starting point, and the initial method IDs are set.
    /// - Relevant transactions are processed:
    ///    - Complete proofs are decompressed, and processed with the `process_complete_proof` method.
    ///    - Chunk proofs are stored in JMT to construct the complete proof body later.
    ///    - Aggregate proofs are processed by concatenating the chunks and processing the complete proof as above.
    ///    - Sequencer commitments are stored in the JMT state by their index.
    ///    - Batch proof method ID transactions are processed to update the batch proof method IDs in the JMT state.
    ///
    /// # Returns
    /// * `RunL1BlockResult` - The result of running the L1 block, contains updates to the L2 state and the light client's JMT state.
    pub fn run_l1_block(
        &self,
        network: Network,
        storage: S,
        witness: Witness,
        da_txs: Vec<DS::BlobTransaction>,
        da_block_header: DS::BlockHeader,
        previous_light_client_proof_output: Option<LightClientCircuitOutput>,
        l2_genesis_root: [u8; 32],
        initial_batch_proof_method_ids: InitialBatchProofMethodIds,
        initial_batch_prover_da_public_key: &[u8],
        initial_sequencer_da_public_key: &[u8],
        initial_security_council_da_addresses: &[Address],
        initial_security_council_threshold: usize,
        security_council_messages_domain: String,
        light_client_proof_method_id: [u32; 8],
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

        let is_lcp_upgrade = previous_light_client_proof_output
            .as_ref()
            .is_some_and(|prev| prev.light_client_proof_method_id != light_client_proof_method_id);

        // If this is the first lcp initialize the batch proof method ids, security council addresses, and DA pub keys
        if previous_light_client_proof_output.is_none() {
            BatchProofMethodIdAccessor::<S>::initialize(
                initial_batch_proof_method_ids,
                &mut working_set,
            );
            SecurityCouncilAddressAccessor::<S>::initialize(
                initial_security_council_da_addresses,
                &mut working_set,
            );
            SecurityCouncilThresholdAccessor::<S>::initialize(
                initial_security_council_threshold,
                &mut working_set,
            );
            SequencerDaPubKeyAccessor::<S>::initialize(
                initial_sequencer_da_public_key,
                &mut working_set,
            );
            BatchProverDaPubKeyAccessor::<S>::initialize(
                initial_batch_prover_da_public_key,
                &mut working_set,
            );
            SecurityCouncilNonceAccessor::<S>::initialize(0, &mut working_set);
        } else if is_lcp_upgrade {
            // LCP circuit upgrade — overwrite JMT state with new circuit's compile-time constants
            BatchProofMethodIdAccessor::<S>::set(initial_batch_proof_method_ids, &mut working_set);
            SecurityCouncilAddressAccessor::<S>::set(
                initial_security_council_da_addresses,
                &mut working_set,
            );
            SecurityCouncilThresholdAccessor::<S>::set(
                initial_security_council_threshold,
                &mut working_set,
            );
            SequencerDaPubKeyAccessor::<S>::set(initial_sequencer_da_public_key, &mut working_set);
            BatchProverDaPubKeyAccessor::<S>::set(
                initial_batch_prover_da_public_key,
                &mut working_set,
            );
            // Initialize nonce only if it doesn't exist yet (upgrading from a version
            // without nonce support). Do NOT reset it if it already exists — that would
            // allow replay of pre-upgrade security council messages.
            if SecurityCouncilNonceAccessor::<S>::get(&mut working_set).is_none() {
                SecurityCouncilNonceAccessor::<S>::set(0, &mut working_set);
            }
        }

        // Read the active pub keys from state (may have been updated by security council)
        let active_batch_prover_da_public_key =
            BatchProverDaPubKeyAccessor::<S>::get(&mut working_set)
                .expect("Batch prover DA public key must exist");
        let active_sequencer_da_public_key = SequencerDaPubKeyAccessor::<S>::get(&mut working_set)
            .expect("Sequencer DA public key must exist");

        // Collect security council transactions to sort by nonce before processing
        let mut sc_txs: Vec<SecurityCouncilTx> = Vec::new();

        'blob_loop: for blob in da_txs {
            let Ok(data) = DataOnDa::try_from_slice(blob.full_data()) else {
                log!("Unparsable blob in da_data, wtxid={:?}", blob.wtxid());
                continue;
            };

            match data {
                // No need to check sender for chunk
                DataOnDa::Chunk(chunk) => {
                    log!("Found chunk");

                    ChunkAccessor::<S>::insert(blob.wtxid(), chunk, &mut working_set);
                }
                DataOnDa::Complete(proof) => {
                    log!("Found complete proof");
                    if blob.sender().as_ref() != active_batch_prover_da_public_key.as_slice() {
                        log!(
                            "Complete proof sender is not batch prover, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }

                    let Ok(proof) = DS::decompress_chunks(&proof) else {
                        log!("Failed to decompress and deserialize complete proof");
                        continue;
                    };

                    match self.process_complete_proof(
                        &proof,
                        last_l2_height,
                        last_sequencer_commitment_index,
                        network,
                        &mut working_set,
                    ) {
                        Ok(()) => {}
                        Err(e) => log!("Error processing complete proof: {e}"),
                    }
                }
                DataOnDa::Aggregate(_, wtxids) => {
                    log!("Found aggregate proof");
                    if blob.sender().as_ref() != active_batch_prover_da_public_key.as_slice() {
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
                            Some(chunk) => {
                                if chunk.len() + complete_proof.len() > MAX_COMPRESSED_BLOB_SIZE {
                                    log!(
                                        "Compressed aggregate too large, wtxid={:?}; skipping",
                                        blob.wtxid()
                                    );
                                    continue 'blob_loop;
                                }

                                complete_proof.extend_from_slice(&chunk);
                            }
                            None => {
                                log!(
                                    "Unknown chunk in aggregate proof, parent={:?}, child={:?}; skipping",
                                    blob.wtxid(),
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
                        network,
                        &mut working_set,
                    ) {
                        Ok(()) => {}
                        // proof resulting from chunk concatenation is not valid
                        // either due to ZK proof being invalid
                        // a deserialization error
                        // or the resulting output was ZK-valid but included an L1 hash
                        // that was not know to the prover
                        Err(e) => {
                            log!("Error processing aggregated proof: {e}");
                        }
                    }
                }
                DataOnDa::SecurityCouncilTx(sc_tx) => {
                    log!("Found security council transaction, collecting for nonce-sorted processing");
                    sc_txs.push(sc_tx);
                }
                DataOnDa::SequencerCommitment(commitment) => {
                    let comm_index = commitment.index;
                    log!("Found sequencer commitment with index {}", comm_index);
                    if blob.sender().as_ref() != active_sequencer_da_public_key.as_slice() {
                        log!(
                            "Sequencer commitment sender is not sequencer, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }
                    let current_epoch = RevertEpochAccessor::<S>::get_or_default(&mut working_set);
                    let existing =
                        SequencerCommitmentAccessor::<S>::get(comm_index, &mut working_set);
                    // Insert if no entry exists, or if existing entry is from a stale epoch
                    if existing.is_none()
                        || SequencerCommitmentEpochAccessor::<S>::get_or_default(
                            comm_index,
                            &mut working_set,
                        ) != current_epoch
                    {
                        SequencerCommitmentAccessor::<S>::insert(
                            comm_index,
                            commitment,
                            &mut working_set,
                        );
                        SequencerCommitmentEpochAccessor::<S>::set(
                            comm_index,
                            current_epoch,
                            &mut working_set,
                        );
                    }
                }
            }
        }

        // Sort security council transactions by nonce and process them in order
        sc_txs.sort_by_key(|tx| tx.tx_type.nonce());
        for sc_tx in sc_txs {
            if let SecurityCouncilTxType::SetLcpToPreviousStateV1(ref body) = sc_tx.tx_type {
                self.process_set_lcp_to_previous_state(
                    sc_tx.clone(),
                    body.clone(),
                    network,
                    &security_council_messages_domain,
                    &mut working_set,
                    &mut last_sequencer_commitment_index,
                    &mut last_l2_state_root,
                    &mut last_l2_height,
                );
            } else {
                self.process_security_council_tx(
                    sc_tx,
                    network,
                    &security_council_messages_domain,
                    &mut working_set,
                );
            }
        }

        // Try to chain proofs using commitments
        // With this setup even if we have valid proofs with commitments like 3,4,5 and 5,6
        // We can update our last commitment index to 6
        let current_epoch = RevertEpochAccessor::<S>::get_or_default(&mut working_set);
        while let Some(sequencer_commitment_info) =
            VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<S>::get(
                last_sequencer_commitment_index + 1,
                &mut working_set,
            )
        {
            // Skip entries from previous epochs (stale data from before a revert)
            let entry_epoch = VerifiedStateTransitionEpochAccessor::<S>::get_or_default(
                last_sequencer_commitment_index + 1,
                &mut working_set,
            );
            if entry_epoch != current_epoch {
                break;
            }

            if sequencer_commitment_info.initial_state_root == last_l2_state_root {
                last_l2_state_root = sequencer_commitment_info.final_state_root;
                last_l2_height = sequencer_commitment_info.last_l2_height;
                last_sequencer_commitment_index += 1;
            } else {
                // This should be infallible
                // this can only happen if commitment started committing to a different chain
                // We make sure in the batch proof circuit that a proof cannot build on a previous commitment
                // but start with a different state root
                unreachable!("Commitment with the next index having an unexpected state root");
            }
        }

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

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

    /// Checks if a threshold value is valid for a given member count.
    ///
    /// A threshold is valid if:
    /// - It is at least `MIN_THRESHOLD`
    /// - It is at most `member_count - MAX_THRESHOLD_PROXIMITY`
    fn is_valid_threshold(threshold: u32, member_count: usize) -> bool {
        let t = threshold as usize;
        t >= MIN_THRESHOLD && t <= member_count.saturating_sub(MAX_THRESHOLD_PROXIMITY)
    }

    /// Processes a security council transaction by dispatching on its type.
    ///
    /// Reads the current security council addresses and threshold from state,
    /// verifies signatures, validates the operation, and applies state changes.
    fn process_security_council_tx(
        &self,
        sc_tx: SecurityCouncilTx,
        network: Network,
        security_council_messages_domain: &str,
        working_set: &mut WorkingSet<S>,
    ) {
        let security_council_addresses = SecurityCouncilAddressAccessor::<S>::get(working_set)
            .expect("Security council addresses must exist");
        let security_council_threshold = SecurityCouncilThresholdAccessor::<S>::get(working_set)
            .expect("Security council threshold must exist");
        let circuit_chain_id = citrea_network_to_chain_id(network);

        // Replay protection: verify and increment nonce
        let msg_nonce = sc_tx.tx_type.nonce();
        let current_nonce = SecurityCouncilNonceAccessor::<S>::get(working_set)
            .expect("Security council nonce must exist");
        let expected_nonce = match current_nonce.checked_add(1) {
            Some(n) => n,
            None => {
                log!("Security council nonce overflow");
                return;
            }
        };
        if msg_nonce != expected_nonce {
            log!(
                "Security council nonce mismatch: expected {}, got {}",
                expected_nonce,
                msg_nonce
            );
            return;
        }

        // Increment nonce immediately after validation (like EVM tx nonce on revert)
        SecurityCouncilNonceAccessor::<S>::set(msg_nonce, working_set);

        match sc_tx.tx_type {
            SecurityCouncilTxType::BatchProofMethodIdUpdateV1(body) => {
                log!("Processing BatchProofMethodIdUpdateV1");
                let batch_proof_method_ids =
                    BatchProofMethodIdAccessor::<S>::get(working_set).unwrap();

                let last_activation_height = batch_proof_method_ids
                    .last()
                    .expect("Should be at least one")
                    .0;

                if body.activation_l2_height <= last_activation_height {
                    log!(
                        "Batch proof method id activation height is not greater than the last one"
                    );
                    return;
                }

                if !verify_security_council_signatures(
                    &security_council_addresses,
                    BatchProofMethodIdUpdate::from(body.clone()),
                    &sc_tx.signatures_with_index,
                    security_council_threshold,
                    security_council_messages_domain.to_string(),
                    circuit_chain_id,
                ) {
                    log!("Method ID security council verification failed");
                    return;
                }

                BatchProofMethodIdAccessor::<S>::insert(
                    body.activation_l2_height,
                    body.method_id,
                    working_set,
                );
            }
            SecurityCouncilTxType::AddSecurityCouncilMemberV1(body) => {
                log!("Processing AddSecurityCouncilMemberV1");
                let new_member_address = Address::from_slice(&body.new_member);

                if !verify_security_council_signatures(
                    &security_council_addresses,
                    AddSecurityCouncilMember::from(body.clone()),
                    &sc_tx.signatures_with_index,
                    security_council_threshold,
                    security_council_messages_domain.to_string(),
                    circuit_chain_id,
                ) {
                    log!("Add member security council verification failed");
                    return;
                }

                if security_council_addresses.contains(&new_member_address) {
                    log!("Member already exists in security council");
                    return;
                }

                let new_count = security_council_addresses.len() + 1;
                if new_count > MAX_NUMBER_OF_MEMBERS_IN_SECURITY_COUNCIL {
                    log!("Adding member would exceed max security council size: new_count={}, max={}", new_count, MAX_NUMBER_OF_MEMBERS_IN_SECURITY_COUNCIL);
                    return;
                }

                if !Self::is_valid_threshold(body.new_threshold, new_count) {
                    log!(
                        "Invalid new threshold for add member: threshold={}, new_count={}",
                        body.new_threshold,
                        new_count
                    );
                    return;
                }

                let mut new_addresses = security_council_addresses.clone();
                new_addresses.push(new_member_address);
                SecurityCouncilAddressAccessor::<S>::set(&new_addresses, working_set);
                SecurityCouncilThresholdAccessor::<S>::set(
                    body.new_threshold as usize,
                    working_set,
                );
            }
            SecurityCouncilTxType::RemoveSecurityCouncilMemberV1(body) => {
                log!("Processing RemoveSecurityCouncilMemberV1");
                let member_address = Address::from_slice(&body.member_to_be_removed);

                if !verify_security_council_signatures(
                    &security_council_addresses,
                    RemoveSecurityCouncilMember::from(body.clone()),
                    &sc_tx.signatures_with_index,
                    security_council_threshold,
                    security_council_messages_domain.to_string(),
                    circuit_chain_id,
                ) {
                    log!("Remove member security council verification failed");
                    return;
                }

                if !security_council_addresses.contains(&member_address) {
                    log!("Member does not exist in security council");
                    return;
                }

                let remaining_count = security_council_addresses.len() - 1;
                if remaining_count < MIN_NUMBER_OF_MEMBERS_IN_SECURITY_COUNCIL {
                    log!("Removing member would go below min security council size: remaining_count={}, min={}", remaining_count, MIN_NUMBER_OF_MEMBERS_IN_SECURITY_COUNCIL);
                    return;
                }

                if !Self::is_valid_threshold(body.new_threshold, remaining_count) {
                    log!(
                        "Invalid new threshold for remove member: threshold={}, remaining_count={}",
                        body.new_threshold,
                        remaining_count
                    );
                    return;
                }

                SecurityCouncilAddressAccessor::<S>::remove(member_address, working_set);
                SecurityCouncilThresholdAccessor::<S>::set(
                    body.new_threshold as usize,
                    working_set,
                );
            }
            SecurityCouncilTxType::UpdateSecurityCouncilThresholdV1(body) => {
                log!("Processing UpdateSecurityCouncilThresholdV1");

                if !verify_security_council_signatures(
                    &security_council_addresses,
                    UpdateSecurityCouncilThreshold::from(body.clone()),
                    &sc_tx.signatures_with_index,
                    security_council_threshold,
                    security_council_messages_domain.to_string(),
                    circuit_chain_id,
                ) {
                    log!("Update threshold security council verification failed");
                    return;
                }

                let member_count = security_council_addresses.len();
                if !Self::is_valid_threshold(body.new_threshold, member_count) {
                    log!(
                        "Invalid new threshold: threshold={}, member_count={}",
                        body.new_threshold,
                        member_count
                    );
                    return;
                }

                SecurityCouncilThresholdAccessor::<S>::set(
                    body.new_threshold as usize,
                    working_set,
                );
            }
            SecurityCouncilTxType::ReplaceSecurityCouncilMemberV1(body) => {
                log!("Processing ReplaceSecurityCouncilMemberV1");
                let old_address = Address::from_slice(&body.to_be_replaced);
                let new_address = Address::from_slice(&body.new_member);

                if !verify_security_council_signatures(
                    &security_council_addresses,
                    ReplaceSecurityCouncilMember::from(body.clone()),
                    &sc_tx.signatures_with_index,
                    security_council_threshold,
                    security_council_messages_domain.to_string(),
                    circuit_chain_id,
                ) {
                    log!("Replace member security council verification failed");
                    return;
                }

                if !security_council_addresses.contains(&old_address) {
                    log!("Member to be replaced does not exist in security council");
                    return;
                }
                if security_council_addresses.contains(&new_address) {
                    log!("New member already exists in security council");
                    return;
                }

                let new_addresses: Vec<Address> = security_council_addresses
                    .iter()
                    .map(|a| if *a == old_address { new_address } else { *a })
                    .collect();
                SecurityCouncilAddressAccessor::<S>::set(&new_addresses, working_set);
            }
            SecurityCouncilTxType::UpdateSequencerDaPubKeyV1(body) => {
                log!("Processing UpdateSequencerDaPubKeyV1");

                if !verify_security_council_signatures(
                    &security_council_addresses,
                    UpdateSequencerDaPubKey::from(body.clone()),
                    &sc_tx.signatures_with_index,
                    security_council_threshold,
                    security_council_messages_domain.to_string(),
                    circuit_chain_id,
                ) {
                    log!("Update sequencer DA pub key security council verification failed");
                    return;
                }

                if body.new_pub_key == [0u8; 33] {
                    log!("New sequencer DA pub key cannot be all zeros");
                    return;
                }

                SequencerDaPubKeyAccessor::<S>::set(&body.new_pub_key, working_set);
            }
            SecurityCouncilTxType::UpdateBatchProverDaPubKeyV1(body) => {
                log!("Processing UpdateBatchProverDaPubKeyV1");

                if !verify_security_council_signatures(
                    &security_council_addresses,
                    UpdateBatchProverDaPubKey::from(body.clone()),
                    &sc_tx.signatures_with_index,
                    security_council_threshold,
                    security_council_messages_domain.to_string(),
                    circuit_chain_id,
                ) {
                    log!("Update batch prover DA pub key security council verification failed");
                    return;
                }

                if body.new_pub_key == [0u8; 33] {
                    log!("New batch prover DA pub key cannot be all zeros");
                    return;
                }

                BatchProverDaPubKeyAccessor::<S>::set(&body.new_pub_key, working_set);
            }
            SecurityCouncilTxType::RemoveBatchProofMethodIdV1(body) => {
                log!("Processing RemoveBatchProofMethodIdV1");

                if !verify_security_council_signatures(
                    &security_council_addresses,
                    RemoveBatchProofMethodId::from(body.clone()),
                    &sc_tx.signatures_with_index,
                    security_council_threshold,
                    security_council_messages_domain.to_string(),
                    circuit_chain_id,
                ) {
                    log!("Remove batch proof method id security council verification failed");
                    return;
                }

                let batch_proof_method_ids =
                    BatchProofMethodIdAccessor::<S>::get(working_set).unwrap();

                if batch_proof_method_ids.len() <= 1 {
                    log!("Cannot remove the last batch proof method id");
                    return;
                }

                let index = body.method_id_index as usize;
                if index >= batch_proof_method_ids.len() {
                    log!(
                        "Method id index out of bounds: index={}, len={}",
                        index,
                        batch_proof_method_ids.len()
                    );
                    return;
                }

                let (stored_height, stored_method_id) = batch_proof_method_ids[index];
                if stored_method_id != body.batch_proof_method_id {
                    log!(
                        "Method id at index does not match: expected {:?}, got {:?}",
                        body.batch_proof_method_id,
                        stored_method_id
                    );
                    return;
                }
                if stored_height != body.l2_activation_height {
                    log!(
                        "Activation height at index does not match: expected {}, got {}",
                        body.l2_activation_height,
                        stored_height
                    );
                    return;
                }

                let mut new_method_ids = batch_proof_method_ids;
                new_method_ids.remove(index);
                BatchProofMethodIdAccessor::<S>::set(new_method_ids, working_set);
            }
            SecurityCouncilTxType::SetLcpToPreviousStateV1(_) => {
                // Handled separately in process_set_lcp_to_previous_state
                unreachable!(
                    "SetLcpToPreviousStateV1 should not reach process_security_council_tx"
                );
            }
        }
    }

    /// Processes a SetLcpToPreviousState security council message.
    ///
    /// This is an emergency operation that reverts the LCP state to a previous sequencer
    /// commitment index. It validates the message fields against stored state, increments
    /// the revert epoch (to invalidate stale verified state transitions), and resets the
    /// chaining state.
    #[allow(clippy::too_many_arguments)]
    fn process_set_lcp_to_previous_state(
        &self,
        sc_tx: SecurityCouncilTx,
        body: SetLcpToPreviousStateV1Body,
        network: Network,
        security_council_messages_domain: &str,
        working_set: &mut WorkingSet<S>,
        last_sequencer_commitment_index: &mut u32,
        last_l2_state_root: &mut [u8; 32],
        last_l2_height: &mut u64,
    ) {
        let security_council_addresses = SecurityCouncilAddressAccessor::<S>::get(working_set)
            .expect("Upgrade authority addresses must exist");
        let security_council_threshold = SecurityCouncilThresholdAccessor::<S>::get(working_set)
            .expect("Security council threshold must exist");
        let circuit_chain_id = citrea_network_to_chain_id(network);

        // Replay protection: verify and increment nonce
        let msg_nonce = sc_tx.tx_type.nonce();
        let current_nonce = SecurityCouncilNonceAccessor::<S>::get(working_set)
            .expect("Security council nonce must exist");
        let expected_nonce = match current_nonce.checked_add(1) {
            Some(n) => n,
            None => {
                log!("Security council nonce overflow");
                return;
            }
        };
        if msg_nonce != expected_nonce {
            log!(
                "Security council nonce mismatch: expected {}, got {}",
                expected_nonce,
                msg_nonce
            );
            return;
        }

        // Increment nonce immediately after validation (like EVM tx nonce on revert)
        SecurityCouncilNonceAccessor::<S>::set(msg_nonce, working_set);

        // Signature verification
        if !verify_security_council_signatures(
            &security_council_addresses,
            SetLcpToPreviousState::from(body.clone()),
            &sc_tx.signatures_with_index,
            security_council_threshold,
            security_council_messages_domain.to_string(),
            circuit_chain_id,
        ) {
            log!("SetLcpToPreviousState security council verification failed");
            return;
        }

        // Validate: index must be less than current last_sequencer_commitment_index
        if body.index >= *last_sequencer_commitment_index {
            log!(
                "Revert index {} is not less than current last_sequencer_commitment_index {}",
                body.index,
                *last_sequencer_commitment_index
            );
            return;
        }

        // Validate: VerifiedStateTransition at the given index must exist and match preStateRoot
        let verified_transition = match VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<
            S,
        >::get(body.index, working_set)
        {
            Some(t) => t,
            None => {
                log!("No verified state transition found at index {}", body.index);
                return;
            }
        };

        if verified_transition.final_state_root != body.pre_state_root {
            log!("preStateRoot does not match final_state_root at the given index");
            return;
        }

        // Validate: SequencerCommitment at the given index must exist and match fields
        let seq_commitment = match SequencerCommitmentAccessor::<S>::get(body.index, working_set) {
            Some(c) => c,
            None => {
                log!("No sequencer commitment found at index {}", body.index);
                return;
            }
        };

        if seq_commitment.l2_end_block_number != body.last_l2_height {
            log!(
                "last_l2_height mismatch: expected {}, got {}",
                seq_commitment.l2_end_block_number,
                body.last_l2_height
            );
            return;
        }

        if seq_commitment.merkle_root != body.merkle_root {
            log!("merkle_root does not match sequencer commitment at the given index");
            return;
        }

        // All checks passed — increment revert epoch
        let current_epoch = RevertEpochAccessor::<S>::get_or_default(working_set);
        let new_epoch = current_epoch + 1;
        RevertEpochAccessor::<S>::set(new_epoch, working_set);

        // Reset chaining state
        *last_sequencer_commitment_index = body.index;
        *last_l2_state_root = body.pre_state_root;
        *last_l2_height = body.last_l2_height;

        log!(
            "LCP reverted to index {}, epoch incremented to {}",
            body.index,
            new_epoch
        );
    }

    /// Called by the guest to run the light client circuit.
    ///
    /// # Arguments
    /// * `da_verifier` - The DA verifier to use for verifying the DA block and its transactions
    /// * `input` - The input to the light client circuit, containing the DA block header, inclusion proof, completeness proof, and previous light client proof, and the witness.
    /// * `storage` - The storage used for accessing the JMT state, performing updates, and validating read and write operations.
    /// * `network` - The Citrea network to use for verifying the DA block header
    /// * `l2_genesis_root` - The L2 genesis root to start the L2 state if there is no previous light client proof
    /// * `initial_batch_proof_method_ids` - To initialize the batch proof method IDs in the JMT state if this is the first light client proof
    /// * `initial_batch_prover_da_public_key` - The initial public key of the batch prover
    /// * `initial_sequencer_da_public_key` - The initial public key of the sequencer
    /// * `initial_security_council_da_addresses` - The initial addresses of the security council, used to initialize the LCP state on first run.
    ///
    /// # Logic
    /// 1. Verifies the previous light client proof and extracts its output.
    /// 2. Uses `DaVerifier::verify_header_chain` to check if the new block header is valid under the Bitcoin consensus rules (including proof-of-work)
    ///    and follows the latest DA block from the previous light client proof. If there is no previous light client proof,
    ///    a predefined constant initial network state is used.
    /// 3. Uses `DaVerifier::verify_transactions` to validate the inclusion and completeness proofs against the block header and retrieve the relevant transactions from the DA block.
    ///    This guarantees that all relevant transactions in the DA block will be processed.
    /// 4. Calls `run_l1_block` to process the DA transactions, and verifying the updates to the L2 state and the JMT state.
    /// 5. Uses `RunL1BlockResult` to generate the output of the light client circuit.
    ///
    /// # Returns
    /// * `Ok(LightClientCircuitOutput)` if the circuit was run successfully
    /// * `Err(LightClientVerificationError)` if there was an error running the circuit.
    #[allow(clippy::too_many_arguments)]
    pub fn run_circuit<DaV>(
        &self,
        da_verifier: DaV,
        input: LightClientCircuitInput<DaV::Spec>,
        storage: S,
        network: Network,
        l2_genesis_root: [u8; 32],
        initial_batch_proof_method_ids: InitialBatchProofMethodIds,
        initial_batch_prover_da_public_key: &[u8],
        initial_sequencer_da_public_key: &[u8],
        initial_security_council_da_addresses: &[Address],
        initial_security_council_threshold: usize,
        security_council_messages_domain: String,
        allowed_previous_lcp_method_ids: &[[u32; 8]],
    ) -> Result<LightClientCircuitOutput, LightClientVerificationError<DaV>>
    where
        DaV: DaVerifier<Spec = DS>,
        Z: ZkvmGuest,
    {
        // from input, parse previous light client proof output
        let previous_light_client_proof_output = if let Some(proof) =
            input.previous_light_client_proof
        {
            // Extract the previous output's method ID from the proof journal (unverified)
            let raw_journal = Z::extract_raw_output(&proof)
                .expect("Should be able to extract journal from previous proof");
            let prev_output_peek: LightClientCircuitOutput = Z::deserialize_output(&raw_journal)
                .expect("Should be able to deserialize previous output");
            let prev_method_id = prev_output_peek.light_client_proof_method_id;

            // Verify the proof with the extracted method ID
            // (verification will fail if the proof wasn't generated by this method ID)
            let prev_output = Z::verify_and_deserialize_output::<LightClientCircuitOutput>(
                &proof,
                &prev_method_id.into(),
                network_to_dev_mode(network),
            )
            .expect("Previous light client proof is invalid");

            // Validate the method ID transition
            if prev_method_id != input.light_client_proof_method_id {
                assert!(
                    allowed_previous_lcp_method_ids.contains(&prev_method_id),
                    "Previous LCP method ID is not in the allowed list"
                );
            }

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
            network,
            storage,
            input.witness,
            da_txs,
            input.da_block_header,
            previous_light_client_proof_output,
            l2_genesis_root,
            initial_batch_proof_method_ids,
            initial_batch_prover_da_public_key,
            initial_sequencer_da_public_key,
            initial_security_council_da_addresses,
            initial_security_council_threshold,
            security_council_messages_domain,
            input.light_client_proof_method_id,
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

/// These are chain ids for the citrea networks
/// This function is mainly used to check the chain id of the
/// method id upgrade transactions and to prevent cross network replay attacks
/// The method id upgrade identifiers are not strictly tied to chain ids
/// but for simplicity we use the same values
pub fn citrea_network_to_chain_id(network: sov_rollup_interface::Network) -> u64 {
    match network {
        sov_rollup_interface::Network::Mainnet => 4114,
        sov_rollup_interface::Network::Testnet => 5115,
        sov_rollup_interface::Network::Devnet => 62298,
        sov_rollup_interface::Network::Nightly => 5665,
        sov_rollup_interface::Network::TestNetworkWithForks => 5665,
    }
}
