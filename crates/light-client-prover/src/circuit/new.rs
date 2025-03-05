use std::collections::BTreeMap;

use borsh::BorshDeserialize;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::{
    BatchProofCircuitOutputV2, BatchProofCircuitOutputV3, BlobReaderTrait, DaSpec,
    StateReaderAndWriter, WorkingSet, Zkvm,
};
use sov_modules_core::{ReadWriteLog, Storage};
use sov_rollup_interface::da::{BatchProofMethodId, DaDataLightClient, DaNamespace, DaVerifier};
use sov_rollup_interface::witness::Witness;
use sov_rollup_interface::zk::batch_proof::output::v1::BatchProofCircuitOutputV1;
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::{
    BatchProofInfo, LightClientCircuitOutput,
};
use sov_rollup_interface::Network;

use super::accessors::BlockHashAccessor;
use super::old::LightClientVerificationError;
use super::InitialBatchProofMethodIds;
use crate::circuit::accessors::ChunkAccessor;
use crate::utils::recursive_match_state_roots;

type CircuitError = &'static str;

struct RunL1BlockResult {
    l2_state_root: [u8; 32],
    lcp_state_root: [u8; 32],
    unchained_batch_proofs_info: Vec<BatchProofInfo>,
    last_l2_height: u64,
    batch_proof_method_ids: Vec<(u64, [u32; 8])>,
    witness: Witness,
}

struct LightClientProofCircuit<S: Storage, DS: DaSpec, Z: Zkvm> {
    phantom: core::marker::PhantomData<(S, DS, Z)>,
}

impl<S: Storage, DS: DaSpec, Z: Zkvm> LightClientProofCircuit<S, DS, Z> {
    fn process_complete_proof(
        &self,
        proof: &[u8],
        batch_proof_method_ids: &InitialBatchProofMethodIds,
        last_l2_height: u64,
        initial_to_final: &mut std::collections::BTreeMap<[u8; 32], ([u8; 32], u64)>,
    ) -> Result<(), CircuitError> {
        let Ok(journal) = Z::extract_raw_output(proof) else {
            return Err("Failed to extract output from proof");
        };

        // TODO: only V3 supported after
        // https://github.com/chainwayxyz/citrea/pull/2017
        let (
            batch_proof_output_initial_state_root,
            batch_proof_output_final_state_root,
            batch_proof_output_last_l2_height,
        ) = if let Ok(output) = Z::deserialize_output::<BatchProofCircuitOutputV3>(&journal) {
            (
                output.initial_state_root,
                output.final_state_root,
                output.last_l2_height,
            )
        } else if let Ok(output) = Z::deserialize_output::<BatchProofCircuitOutputV2>(&journal) {
            (
                output.initial_state_root,
                output.final_state_root,
                output.last_l2_height,
            )
        } else if let Ok(output) = Z::deserialize_output::<BatchProofCircuitOutputV1>(&journal) {
            (output.initial_state_root, output.final_state_root, 0)
        } else {
            return Err("Failed to parse proof");
        };

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

        // TODO: this needs serialized proof
        // if index is not in the expected to fail hints, then it should pass
        Z::verify(proof, &batch_proof_method_id.into()).expect("Proof hinted to pass failed");

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

    // will be called by the circuit and native
    fn run_l1_block(
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
    ) -> RunL1BlockResult {
        let mut working_set =
            WorkingSet::with_witness(storage.clone(), witness, Default::default());

        // first insert the block hash into the JMT
        BlockHashAccessor::<S>::insert(da_block_header.hash().into(), &mut working_set);

        // Mapping from initial state root to final state root and last L2 height
        let mut initial_to_final = BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

        let (mut last_state_root, mut last_l2_height) =
            previous_light_client_proof_output.as_ref().map_or_else(
                || {
                    // if no previous proof, we start from genesis state root
                    (l2_genesis_root, 0)
                },
                |prev_journal| (prev_journal.state_root, prev_journal.last_l2_height),
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

        for blob in da_txs {
            let Ok(data) = DaDataLightClient::try_from_slice(blob.full_data()) else {
                println!("Unparseable blob in da_data, wtxid={:?}", blob.wtxid());
                continue;
            };

            match data {
                // No need to check sender for chunk
                DaDataLightClient::Chunk(chunk) => {
                    println!("Found chunk");

                    ChunkAccessor::<S>::insert(
                        blob.wtxid().expect("Chunk should have wtxid"),
                        chunk,
                        &mut working_set,
                    );
                }
                DaDataLightClient::Complete(proof) => {
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
                    ) {
                        Ok(()) => {}
                        Err(e) => println!("Error processing complete proof: {e}"),
                    }
                }
                DaDataLightClient::Aggregate(_, wtxids) => {
                    println!("Found aggregate proof");
                    if blob.sender().as_ref() != batch_prover_da_public_key {
                        println!(
                            "Aggregate proof sender is not batch prover, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }

                    let mut chunks = Vec::with_capacity(wtxids.len());

                    // Ensure that aggregate has all the needed chunks.
                    for wtxid in &wtxids {
                        match ChunkAccessor::<S>::get(*wtxid, &mut working_set) {
                            Some(body) => chunks.push(body),
                            None => {
                                println!(
                                    "Unknown chunk in aggregate proof, wtxid={:?} skipping",
                                    wtxid
                                );
                                continue;
                            }
                        }
                    }

                    println!("Aggregate has all needed chunks!",);

                    let complete_proof: Vec<_> = chunks.into_iter().flatten().collect();

                    // TODO: figure out how to do this.
                    let Ok(complete_proof) = DS::decompress_chunks(&complete_proof) else {
                        println!("Failed to decompress and deserialize completed chunks");
                        continue;
                    };

                    match self.process_complete_proof(
                        &complete_proof,
                        &batch_proof_method_ids,
                        last_l2_height,
                        &mut initial_to_final,
                    ) {
                        Ok(()) => {}
                        // serialization or duplicate proof error
                        Err(e) => {
                            println!("Error processing aggregated proof: {e}");
                        }
                    }
                }
                DaDataLightClient::BatchProofMethodId(BatchProofMethodId {
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
            }
        }

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        // TODO: compute_state_update cretes state diff
        // which we don't need in this circuit
        // maybe create new function or pass argument for state diff building
        let (lcp_state_root_transition, jmt_state_update, _) = storage
            .compute_state_update(&read_write_log, &mut witness)
            .expect("jellyfish merkle tree update must succeed");

        storage.commit(&jmt_state_update, &vec![], &ReadWriteLog::default());

        RunL1BlockResult {
            l2_state_root: todo!(),
            lcp_state_root: lcp_state_root_transition.final_root,
            unchained_batch_proofs_info: todo!(),
            last_l2_height: todo!(),
            batch_proof_method_ids: todo!(),
            witness,
        }
    }

    // will only called by the circuit
    fn run_circuit<DaV>(
        &self,
        da_verifier: DaV,
        input: LightClientCircuitInput<DaV::Spec>,
        l2_genesis_root: [u8; 32],
        initial_batch_proof_method_ids: InitialBatchProofMethodIds,
        batch_prover_da_public_key: &[u8],
        method_id_upgrade_authority_da_public_key: &[u8],
        network: Network,
        storage: S,
        witness: Witness,
    ) -> Result<LightClientCircuitOutput, LightClientVerificationError<DaV>>
    where
        DaV: DaVerifier<Spec = DS>,
    {
        // from input, parse previous light client proof output
        let previous_light_client_proof_output = if let Some(journal) =
            input.previous_light_client_proof_journal
        {
            let prev_output = Z::verify_and_deserialize_output::<LightClientCircuitOutput>(
                &journal,
                &input.light_client_proof_method_id.into(),
            )
            .map_err(|_| LightClientVerificationError::<DaV>::InvalidPreviousLightClientProof)?;
            // Ensure method IDs match
            assert_eq!(
                input.light_client_proof_method_id,
                prev_output.light_client_proof_method_id,
            );
            Some(prev_output)
        } else {
            None
        };

        // make header chain verification and insert block hash to JMT
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
                DaNamespace::ToLightClientProver,
            )
            .map_err(|err| LightClientVerificationError::DaTxsCouldntBeVerified(err))?;

        // then we can call run_l1_block to run the logic of the circuit
        let result = self.run_l1_block(
            storage,
            witness,
            da_txs,
            input.da_block_header,
            previous_light_client_proof_output,
            l2_genesis_root,
            initial_batch_proof_method_ids,
            batch_prover_da_public_key,
            method_id_upgrade_authority_da_public_key,
        );

        Ok(LightClientCircuitOutput {
            state_root: result.lcp_state_root,
            light_client_proof_method_id: input.light_client_proof_method_id,
            latest_da_state: new_da_state,
            unchained_batch_proofs_info: result.unchained_batch_proofs_info,
            last_l2_height: result.last_l2_height,
            batch_proof_method_ids: result.batch_proof_method_ids,
            mmr_guest: todo!("will be removed"),
        })
    }
}
