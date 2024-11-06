use borsh::BorshDeserialize;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{DaDataLightClient, DaNamespace, DaVerifier};
use sov_rollup_interface::zk::{
    BatchProofCircuitOutput, BatchProofInfo, LightClientCircuitInput, LightClientCircuitOutput,
    ZkvmGuest,
};

#[derive(Debug)]
pub enum LightClientVerificationError {
    DaTxsCouldntBeVerified,
}

pub fn run_circuit<DaV: DaVerifier, G: ZkvmGuest>(
    da_verifier: DaV,
    guest: &G,
) -> Result<LightClientCircuitOutput, LightClientVerificationError> {
    let input: LightClientCircuitInput<DaV::Spec> = guest.read_from_host();

    // Verify the previous light client proof if it exists
    let deserialized_previous_light_client_proof_journal = input
        .light_client_proof_journal
        .as_ref()
        .map(|proof_journal| {
            let deserialized = G::verify_and_extract_output::<LightClientCircuitOutput>(
                proof_journal,
                &input.light_client_proof_method_id.into(),
            )
            .expect("Should have verified the light client proof");

            // Ensure input and output method IDs match
            // TODO: Once we have light client method id by spec update accordingly
            assert_eq!(
                input.light_client_proof_method_id,
                deserialized.light_client_proof_method_id
            );
            deserialized
        });

    // Verify data from da
    let _validity_condition = da_verifier
        .verify_transactions(
            &input.da_block_header,
            input.da_data.as_slice(),
            input.inclusion_proof,
            input.completeness_proof,
            DaNamespace::ToLightClientProver,
        )
        .map_err(|_| LightClientVerificationError::DaTxsCouldntBeVerified)?;

    let mut complete_proofs = vec![];
    // Try parsing the data
    for blob in input.da_data {
        if blob.sender().as_ref() == input.batch_prover_da_pub_key {
            let data = DaDataLightClient::try_from_slice(blob.verified_data());

            if let Ok(data) = data {
                match data {
                    DaDataLightClient::Complete(proof) => {
                        complete_proofs.push(proof);
                    }
                    DaDataLightClient::Aggregate(_) => todo!(),
                    DaDataLightClient::Chunk(_) => todo!(),
                }
            }
        }
    }

    // Deserialize batch proof journals
    let deserialized_outputs: Vec<_> = input
        .batch_proof_journals
        .iter()
        .map(|journal| {
            G::verify_and_extract_output::<BatchProofCircuitOutput<DaV::Spec, [u8; 32]>>(
                journal,
                &input.batch_proof_method_id.into(),
            )
            .expect("Should have verified and extracted the batch proof")
        })
        .collect();

    // Mapping from initial state root to final state root and last L2 height
    let mut initial_to_final = std::collections::BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

    let mut unverified_outputs = vec![];

    let mut last_state_root = [0u8; 32];
    let mut last_l2_height = 0;

    // If we have a previous light client proof, check they can be chained
    // If not, skip for now
    // TODO: Once we have a manually planted light client proof use that and assume prev light client proof always exists
    // So there will be no need for all these if lets
    if let Some(previous_output) = &deserialized_previous_light_client_proof_journal {
        last_l2_height = previous_output.last_l2_height;
        last_state_root = previous_output.state_root;
        for unverified_info in previous_output.unverified_batch_proofs_info.iter() {
            if unverified_info.last_l2_height <= previous_output.last_l2_height {
                continue;
            }
            // Add them directly as they are the ones that could not be matched
            initial_to_final.insert(
                unverified_info.initial_state_root,
                (
                    unverified_info.final_state_root,
                    unverified_info.last_l2_height,
                ),
            );
        }

        for output in deserialized_outputs.iter() {
            if output.last_l2_height <= previous_output.last_l2_height {
                continue;
            }
            recursive_match_state_roots(
                &mut initial_to_final,
                &BatchProofInfo::new(
                    previous_output.state_root,
                    output.final_state_root,
                    output.last_l2_height,
                ),
            );
        }

        // Do recursive matching for previous state root
        recursive_match_state_roots(
            &mut initial_to_final,
            &BatchProofInfo::new(
                previous_output.state_root,
                previous_output.state_root,
                previous_output.last_l2_height,
            ),
        );
        // Now only thing left is the state update if exists and others are unverified
        if let Some((final_root, last_l2)) = initial_to_final.remove(&previous_output.state_root) {
            last_l2_height = last_l2;
            last_state_root = final_root;
        }

        // Collect unverified outputs
        unverified_outputs = initial_to_final
            .into_iter()
            .map(
                |(initial_state_root, (final_state_root, last_l2_height))| BatchProofInfo {
                    initial_state_root,
                    final_state_root,
                    last_l2_height,
                },
            )
            .collect::<Vec<_>>();
    }

    Ok(LightClientCircuitOutput {
        state_root: last_state_root,
        light_client_proof_method_id: input.light_client_proof_method_id,
        unverified_batch_proofs_info: unverified_outputs,
        last_l2_height,
    })
}

fn recursive_match_state_roots(
    initial_to_final: &mut std::collections::BTreeMap<[u8; 32], ([u8; 32], u64)>,
    bp_info: &BatchProofInfo,
) {
    if let Some((final_root, last_l2)) = initial_to_final.remove(&bp_info.final_state_root) {
        recursive_match_state_roots(
            initial_to_final,
            &BatchProofInfo::new(bp_info.initial_state_root, final_root, last_l2),
        );
    } else {
        initial_to_final.insert(
            bp_info.initial_state_root,
            (bp_info.final_state_root, bp_info.last_l2_height),
        );
    }
}

#[test]
fn test_recursive_match_state_roots() {
    let mut initial_to_final = std::collections::BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

    let bp_info = BatchProofInfo::new([2u8; 32], [3u8; 32], 1);
    initial_to_final.insert([1u8; 32], ([2u8; 32], 1));
    initial_to_final.insert([3u8; 32], ([4u8; 32], 3));
    initial_to_final.insert([4u8; 32], ([5u8; 32], 4));
    // First of all this should chain 2 to 5 from 2-3 -> 3-4 -> 4-5
    recursive_match_state_roots(&mut initial_to_final, &bp_info);

    assert_eq!(initial_to_final.len(), 2);

    let first = initial_to_final.get(&[1u8; 32]).unwrap();
    assert_eq!(first.0, [2u8; 32]);

    let second = initial_to_final.get(&[2u8; 32]).unwrap();
    assert_eq!(second.0, [5u8; 32]);

    let bp_info_prev_state = BatchProofInfo::new([1u8; 32], [1u8; 32], 0);

    recursive_match_state_roots(&mut initial_to_final, &bp_info_prev_state);

    let only = initial_to_final.get(&[1u8; 32]).unwrap();
    assert_eq!(only.0, [5u8; 32]);

    assert_eq!(initial_to_final.len(), 1);
}

#[test]
fn test_recursive_match_state_roots_empty_btreemap() {
    let mut initial_to_final = std::collections::BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

    let bp_info = BatchProofInfo::new([2u8; 32], [3u8; 32], 1);
    // First of all this should chain 2 to 5 from 2-3 -> 3-4 -> 4-5
    recursive_match_state_roots(&mut initial_to_final, &bp_info);

    assert_eq!(initial_to_final.len(), 1);

    let first = initial_to_final.get(&[2u8; 32]).unwrap();
    assert_eq!(first.0, [3u8; 32]);
}

#[test]
fn test_recursive_match_state_roots_with_unchainable_elements() {
    let mut initial_to_final = std::collections::BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

    let bp_info = BatchProofInfo::new([45u8; 32], [46u8; 32], 45);
    initial_to_final.insert([1u8; 32], ([2u8; 32], 1));
    initial_to_final.insert([3u8; 32], ([5u8; 32], 3));
    initial_to_final.insert([6u8; 32], ([7u8; 32], 6));

    recursive_match_state_roots(&mut initial_to_final, &bp_info);

    assert_eq!(initial_to_final.len(), 4);

    let first = initial_to_final.get(&[1u8; 32]).unwrap();
    assert_eq!(first.0, [2u8; 32]);

    let none = initial_to_final.get(&[2u8; 32]);
    assert!(none.is_none());

    let second = initial_to_final.get(&[3u8; 32]).unwrap();
    assert_eq!(second.0, [5u8; 32]);
    assert_eq!(second.1, 3);

    let third = initial_to_final.get(&[6u8; 32]).unwrap();
    assert_eq!(third.0, [7u8; 32]);
    assert_eq!(third.1, 6);

    let fourth = initial_to_final.get(&[45u8; 32]).unwrap();
    assert_eq!(fourth.0, [46u8; 32]);
    assert_eq!(fourth.1, 45);
}
