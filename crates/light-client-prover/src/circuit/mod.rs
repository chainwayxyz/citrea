use std::collections::BTreeMap;

use accessors::{BlockHashAccessor, ChunkAccessor, SequencerCommitmentAccessor};
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
    BatchProofInfo, LightClientCircuitOutput,
};
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;

use crate::circuit::utils::{collect_unchained_outputs, recursive_match_state_roots};

/// Accessor (helpers) that are used inside the light client proof circuit.
/// To access certain information that was saved to its state at one point.
pub(crate) mod accessors;
/// Initial values that are used to initialize the light client proof circuit.
pub mod initial_values;
pub(crate) mod utils;

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
    lcp_state_root: [u8; 32],
    unchained_batch_proofs_info: Vec<BatchProofInfo>,
    last_l2_height: u64,
    batch_proof_method_ids: Vec<(u64, [u32; 8])>,
    pub witness: Witness,
    pub change_set: S,
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

    fn process_complete_proof(
        &self,
        proof: &[u8],
        batch_proof_method_ids: &InitialBatchProofMethodIds,
        last_l2_height: u64,
        initial_to_final: &mut std::collections::BTreeMap<[u8; 32], ([u8; 32], u64)>,
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

        let batch_proof_output_initial_state_root = batch_proof_output.initial_state_root();
        let batch_proof_output_final_state_root = batch_proof_output.final_state_root();
        let batch_proof_output_last_l2_height = batch_proof_output.last_l2_height();

        // Do not add if last l2 height is smaller or equal to previous output
        // This is to defend against replay attacks, for example if somehow there is the script of batch proof 1 we do not need to go through it again
        if batch_proof_output_last_l2_height <= last_l2_height && last_l2_height != 0 {
            return Err("Last L2 height is less than proof's last l2 height");
        }

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

        println!("Using batch proof method id {:?}", batch_proof_method_id);

        Z::verify(proof, &batch_proof_method_id.into()).map_err(|_| "Failed to verify proof")?;

        recursive_match_state_roots(
            initial_to_final,
            &BatchProofInfo::new(
                batch_proof_output_initial_state_root,
                batch_proof_output_final_state_root,
                batch_proof_output_last_l2_height,
            ),
        );

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
        method_id_upgrade_authority_da_public_key: &[u8],
    ) -> RunL1BlockResult<S> {
        let mut working_set =
            WorkingSet::with_witness(storage.clone(), witness, Default::default());

        // first insert the block hash into the JMT
        BlockHashAccessor::<S>::insert(da_block_header.hash().into(), &mut working_set);

        // Mapping from initial state root to final state root and last L2 height
        let mut initial_to_final = BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

        let (mut last_l2_state_root, mut last_l2_height) =
            previous_light_client_proof_output.as_ref().map_or_else(
                || {
                    // if no previous proof, we start from genesis state root
                    (l2_genesis_root, 0)
                },
                |prev_journal| (prev_journal.l2_state_root, prev_journal.last_l2_height),
            );

        // If we have a previous light client proof, check they can be chained
        // If not, skip for now
        if let Some(previous_output) = &previous_light_client_proof_output {
            for unchained_info in previous_output.unchained_batch_proofs_info.iter() {
                // Add them directly as they are the ones that could not be matched
                initial_to_final.insert(
                    unchained_info.initial_state_root,
                    (
                        unchained_info.final_state_root,
                        unchained_info.last_l2_height,
                    ),
                );
            }
        }

        let mut batch_proof_method_ids = previous_light_client_proof_output
            .as_ref()
            .map_or(initial_batch_proof_method_ids, |o| {
                o.batch_proof_method_ids.clone()
            });

        'blob_loop: for blob in da_txs {
            let Ok(data) = DataOnDa::try_from_slice(blob.full_data()) else {
                println!("Unparseable blob in da_data, wtxid={:?}", blob.wtxid());
                continue;
            };

            match data {
                // No need to check sender for chunk
                DataOnDa::Chunk(chunk) => {
                    println!("Found chunk");

                    ChunkAccessor::<S>::insert(
                        blob.wtxid().expect("Chunk should have wtxid"),
                        chunk,
                        &mut working_set,
                    );
                }
                DataOnDa::Complete(proof) => {
                    println!("Found complete proof");
                    if blob.sender().as_ref() != batch_prover_da_public_key {
                        println!(
                            "Complete proof sender is not batch prover, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }

                    match self.process_complete_proof(
                        &proof,
                        &batch_proof_method_ids,
                        last_l2_height,
                        &mut initial_to_final,
                        &mut working_set,
                    ) {
                        Ok(()) => {}
                        Err(e) => println!("Error processing complete proof: {e}"),
                    }
                }
                DataOnDa::Aggregate(_, wtxids) => {
                    println!("Found aggregate proof");
                    if blob.sender().as_ref() != batch_prover_da_public_key {
                        println!(
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
                                println!(
                                    "Unknown chunk in aggregate proof, wtxid={:?} skipping",
                                    wtxid
                                );
                                continue 'blob_loop;
                            }
                        }
                    }

                    println!("Aggregate has all needed chunks!");

                    let Ok(complete_proof) = DS::decompress_chunks(&complete_proof) else {
                        println!("Failed to decompress and deserialize completed chunks");
                        continue;
                    };

                    match self.process_complete_proof(
                        &complete_proof,
                        &batch_proof_method_ids,
                        last_l2_height,
                        &mut initial_to_final,
                        &mut working_set,
                    ) {
                        Ok(()) => {}
                        // proof resulting from chunk concatanation is not valid
                        // either due to ZK proof being invalid
                        // a deserialization error
                        // or the resulting output was ZK-valid but included an L1 hash
                        // that was not know to the prover
                        Err(e) => {
                            println!("Error processing aggregated proof: {e}");
                        }
                    }
                }
                DataOnDa::BatchProofMethodId(BatchProofMethodId {
                    method_id,
                    activation_l2_height,
                }) => {
                    println!("Found batch proof method id");
                    if blob.sender().as_ref() != method_id_upgrade_authority_da_public_key {
                        println!(
                            "Batch proof method id sender is not upgrade authority, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }

                    let last_activation_height = batch_proof_method_ids
                        .last()
                        .expect("Should be at least one")
                        .0;

                    if activation_l2_height > last_activation_height {
                        batch_proof_method_ids.push((activation_l2_height, method_id));
                    }
                }
                DataOnDa::SequencerCommitment(commitment) => {
                    println!("Found sequencer commitment with index {}", commitment.index);
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

        // Do recursive matching for previous state root
        recursive_match_state_roots(
            &mut initial_to_final,
            &BatchProofInfo::new(last_l2_state_root, last_l2_state_root, last_l2_height),
        );

        // Now only thing left is the state update if exists and others are unchained
        if let Some((final_root, last_l2)) = initial_to_final.remove(&last_l2_state_root) {
            last_l2_height = last_l2;
            last_l2_state_root = final_root;
        }

        // Collect unchained outputs
        let unchained_outputs = collect_unchained_outputs(&initial_to_final, last_l2_height);

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
            unchained_batch_proofs_info: unchained_outputs,
            last_l2_height,
            batch_proof_method_ids,
            witness,
            change_set: storage,
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
        method_id_upgrade_authority_da_public_key: &[u8],
    ) -> Result<LightClientCircuitOutput, LightClientVerificationError<DaV>>
    where
        DaV: DaVerifier<Spec = DS>,
        Z: ZkvmGuest,
    {
        // from input, parse previous light client proof output
        let previous_light_client_proof_output =
            if let Some(journal) = input.previous_light_client_proof_journal {
                // previous LCP is verified with the assumption API
                // this would panic if the prev LCP cant be verified
                Z::verify_with_assumptions(&journal, &input.light_client_proof_method_id.into());

                let prev_output: LightClientCircuitOutput = Z::deserialize_output(&journal)
                    .map_err(|_| {
                        LightClientVerificationError::<DaV>::InvalidPreviousLightClientProof
                    })?;

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
            method_id_upgrade_authority_da_public_key,
        );

        Ok(LightClientCircuitOutput {
            l2_state_root: result.l2_state_root,
            light_client_proof_method_id: input.light_client_proof_method_id,
            latest_da_state: new_da_state,
            unchained_batch_proofs_info: result.unchained_batch_proofs_info,
            last_l2_height: result.last_l2_height,
            batch_proof_method_ids: result.batch_proof_method_ids,
            lcp_state_root: result.lcp_state_root,
        })
    }
}

impl<S: Storage, DS: DaSpec, Z: Zkvm> Default for LightClientProofCircuit<S, DS, Z> {
    fn default() -> Self {
        Self::new()
    }
}
