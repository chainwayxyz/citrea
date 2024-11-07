use core::panic;

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

    let unchained_outputs;

    let mut last_state_root;
    let mut last_l2_height;
    let l2_genesis_state_root;

    // If we have a previous light client proof, check they can be chained
    // If not, skip for now
    // TODO: Once we have a manually planted light client proof use that and assume prev light client proof always exists
    // So there will be no need for all these if lets
    if let Some(previous_output) = &deserialized_previous_light_client_proof_journal {
        l2_genesis_state_root = previous_output.l2_genesis_state_root;
        last_l2_height = previous_output.last_l2_height;
        last_state_root = previous_output.state_root;
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

        for output in deserialized_outputs.iter() {
            // Do not add if last l2 height is smaller or equal to previous output
            // This is to defend against replay attacks, for example if somehow there is the script of batch proof 1 we do not need to go through it again
            if output.last_l2_height <= previous_output.last_l2_height {
                continue;
            }
            recursive_match_state_roots(
                &mut initial_to_final,
                &BatchProofInfo::new(
                    output.initial_state_root,
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
        // Now only thing left is the state update if exists and others are unchained
        if let Some((final_root, last_l2)) = initial_to_final.remove(&previous_output.state_root) {
            last_l2_height = last_l2;
            last_state_root = final_root;
        }

        // Collect unchained outputs
        unchained_outputs = collect_unchained_outputs(&mut initial_to_final, last_l2_height);
    }
    // First light client proof
    else if let Some(genesis_state_root) = input.l2_genesis_state_root {
        l2_genesis_state_root = genesis_state_root;
        last_l2_height = 0;
        last_state_root = genesis_state_root;

        for output in deserialized_outputs.iter() {
            recursive_match_state_roots(
                &mut initial_to_final,
                &BatchProofInfo::new(
                    output.initial_state_root,
                    output.final_state_root,
                    output.last_l2_height,
                ),
            );
        }

        // Do recursive matching for previous/genesis state root
        recursive_match_state_roots(
            &mut initial_to_final,
            &BatchProofInfo::new(genesis_state_root, genesis_state_root, 0),
        );
        // Now only thing left is the state update if exists and others are unchained
        if let Some((final_root, last_l2)) = initial_to_final.remove(&genesis_state_root) {
            last_l2_height = last_l2;
            last_state_root = final_root;
        }

        // Collect unchained outputs
        unchained_outputs = collect_unchained_outputs(&mut initial_to_final, last_l2_height);
    } else {
        panic!("Should have either a previous light client proof or a genesis state root");
    }

    Ok(LightClientCircuitOutput {
        state_root: last_state_root,
        light_client_proof_method_id: input.light_client_proof_method_id,
        unchained_batch_proofs_info: unchained_outputs,
        last_l2_height,
        l2_genesis_state_root,
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

fn collect_unchained_outputs(
    initial_to_final: &std::collections::BTreeMap<[u8; 32], ([u8; 32], u64)>,
    // This should not get anything less than the last l2 height
    state_root_l2_height: u64,
) -> Vec<BatchProofInfo> {
    initial_to_final
        .iter()
        .filter(|&(_, &(_, last_l2_height))| last_l2_height > state_root_l2_height)
        .map(
            |(&initial_state_root, &(final_state_root, last_l2_height))| BatchProofInfo {
                initial_state_root,
                final_state_root,
                last_l2_height,
            },
        )
        .collect()
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

    let mut last_l2_height = 0;
    let mut last_state_root = [0u8; 32];
    if let Some((final_root, last_l2)) =
        initial_to_final.remove(&bp_info_prev_state.final_state_root)
    {
        last_l2_height = last_l2;
        last_state_root = final_root;
    }

    assert_eq!(last_l2_height, 4);
    assert_eq!(last_state_root, [5u8; 32]);
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

    let bp_info = BatchProofInfo::new([45u8; 32], [46u8; 32], 46);
    initial_to_final.insert([1u8; 32], ([2u8; 32], 2));
    initial_to_final.insert([3u8; 32], ([5u8; 32], 5));
    initial_to_final.insert([6u8; 32], ([7u8; 32], 7));

    recursive_match_state_roots(&mut initial_to_final, &bp_info);

    assert_eq!(initial_to_final.len(), 4);

    let first = initial_to_final.get(&[1u8; 32]).unwrap();
    assert_eq!(first.0, [2u8; 32]);

    let none = initial_to_final.get(&[2u8; 32]);
    assert!(none.is_none());

    let second = initial_to_final.get(&[3u8; 32]).unwrap();
    assert_eq!(second.0, [5u8; 32]);
    assert_eq!(second.1, 5);

    let third = initial_to_final.get(&[6u8; 32]).unwrap();
    assert_eq!(third.0, [7u8; 32]);
    assert_eq!(third.1, 7);

    let fourth = initial_to_final.get(&[45u8; 32]).unwrap();
    assert_eq!(fourth.0, [46u8; 32]);
    assert_eq!(fourth.1, 46);

    let bp_info_prev = BatchProofInfo::new([1u8; 32], [1u8; 32], 1);

    recursive_match_state_roots(&mut initial_to_final, &bp_info_prev);

    assert_eq!(initial_to_final.len(), 4);

    let first = initial_to_final.get(&[1u8; 32]).unwrap();
    assert_eq!(first.0, [2u8; 32]);

    let mut last_l2_height = 0;
    let mut last_state_root = [0u8; 32];
    if let Some((final_root, last_l2)) = initial_to_final.remove(&bp_info_prev.final_state_root) {
        last_l2_height = last_l2;
        last_state_root = final_root;
    }

    assert_eq!(last_l2_height, 2);
    assert_eq!(last_state_root, [2u8; 32]);

    let unchained_outputs = collect_unchained_outputs(&mut initial_to_final, last_l2_height);
    assert_eq!(unchained_outputs.len(), 3);
    assert_eq!(unchained_outputs[0].initial_state_root, [3u8; 32]);
    assert_eq!(unchained_outputs[1].initial_state_root, [6u8; 32]);
    assert_eq!(unchained_outputs[2].initial_state_root, [45u8; 32]);
}

#[test]
fn test_recursive_match_state_roots_with_genesis_state_root() {
    let mut initial_to_final = std::collections::BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

    let genesis_bp_info = BatchProofInfo::new([0u8; 32], [0u8; 32], 0);
    // Let there be some batch proofs in that DA block
    let bp1 = BatchProofInfo::new([1u8; 32], [2u8; 32], 2);
    let bp2 = BatchProofInfo::new([3u8; 32], [5u8; 32], 5);
    let bp3 = BatchProofInfo::new([6u8; 32], [7u8; 32], 7);

    recursive_match_state_roots(&mut initial_to_final, &bp1);
    // Assert that bp1 is in
    assert_eq!(initial_to_final.len(), 1);
    let elem = initial_to_final.get(&[1u8; 32]).unwrap();
    assert_eq!(elem.0, [2u8; 32]);

    recursive_match_state_roots(&mut initial_to_final, &bp2);
    assert_eq!(initial_to_final.len(), 2);
    let elem = initial_to_final.get(&[3u8; 32]).unwrap();
    assert_eq!(elem.0, [5u8; 32]);

    recursive_match_state_roots(&mut initial_to_final, &bp3);
    assert_eq!(initial_to_final.len(), 3);
    let elem = initial_to_final.get(&[6u8; 32]).unwrap();
    assert_eq!(elem.0, [7u8; 32]);

    // Now let's try to chain them all to genesis state root
    recursive_match_state_roots(&mut initial_to_final, &genesis_bp_info);
    // Unfortunately we are missing the batch proof of state transition from 0 to 1!
    // So we will send all to the other light client proof and hope that it will chain them all
    assert_eq!(initial_to_final.len(), 4);

    /*

    0 0         0 1
    1 2
    3 5
    6 7
    --------------- after 0 -> 1 arrived
    0-2
    3-5
    6-7
     */
    // Look! A new DA block arrived with the batch proof of 0 -> 1
    let bp0_1 = BatchProofInfo::new([0u8; 32], [1u8; 32], 1);
    // This should match 0-2 using 0-0 -> 0-1 -> 1-2
    recursive_match_state_roots(&mut initial_to_final, &bp0_1);

    assert_eq!(initial_to_final.len(), 3);
    let elem = initial_to_final.get(&[0u8; 32]).unwrap();
    assert_eq!(elem.0, [2u8; 32]);

    // call recursive match state roots with the previous output like we do in the circuit
    recursive_match_state_roots(&mut initial_to_final, &genesis_bp_info);
    // Nothing should change in this case
    assert_eq!(initial_to_final.len(), 3);
    let elem = initial_to_final.get(&[0u8; 32]).unwrap();
    assert_eq!(elem.0, [2u8; 32]);
    assert_eq!(elem.1, 2);

    // Last state root right now is 2, last l2 height is also 2

    /*


    btree map
    0-2           0-1 // Oh no! Another DA block arrived with the batch proof of 0-1 some one is trying to replay attack our circuit!
    3-5
    6-7
    --------------- after 0 -> 1 arrived
    0-2          Ignored because of the replay attack
    3-5
    6-7
     */
    // This cannot go in the btreemap because its last l2 height is smaller than or equal to the last l2 height of the previous output

    /*
       btree map
       0-2           2-3
       3-5           7-8
       6-7           8-9
       --------------- after 2 -> 3 and 7-8, 8-9 arrived
       0-2
       2-5
       6-7
       7-8
       8-9
       ---------------- after prev state root is called
       0-2
       2-5
       6-7
       7-8
       8-9
    */
    let bp2_3 = BatchProofInfo::new([2u8; 32], [3u8; 32], 3);
    let bp7_8 = BatchProofInfo::new([7u8; 32], [8u8; 32], 8);
    let bp8_9 = BatchProofInfo::new([8u8; 32], [9u8; 32], 9);

    recursive_match_state_roots(&mut initial_to_final, &bp2_3);
    recursive_match_state_roots(&mut initial_to_final, &bp7_8);
    recursive_match_state_roots(&mut initial_to_final, &bp8_9);

    assert_eq!(initial_to_final.len(), 5);
    let elem = initial_to_final.get(&[0u8; 32]).unwrap();
    assert_eq!(elem.0, [2u8; 32]);
    let elem = initial_to_final.get(&[2u8; 32]).unwrap();
    assert_eq!(elem.0, [5u8; 32]);
    let elem = initial_to_final.get(&[6u8; 32]).unwrap();
    assert_eq!(elem.0, [7u8; 32]);

    // Lets call with last state root
    let bp_sr = BatchProofInfo::new([2u8; 32], [2u8; 32], 2);
    recursive_match_state_roots(&mut initial_to_final, &bp_sr);
    assert_eq!(initial_to_final.len(), 5);
    let elem = initial_to_final.get(&[0u8; 32]).unwrap();
    assert_eq!(elem.0, [2u8; 32]);
    let elem = initial_to_final.get(&[2u8; 32]).unwrap();
    assert_eq!(elem.0, [5u8; 32]);

    // This will throw
    let res = collect_unchained_outputs(&mut initial_to_final, 5);
    assert_eq!(res.len(), 3);
    assert_eq!(res[0].initial_state_root, [6u8; 32]);
    assert_eq!(res[1].initial_state_root, [7u8; 32]);
    assert_eq!(res[2].initial_state_root, [8u8; 32]);
    // After this 6-7, 7-8 and 8-9 will be moved to the next light client proof

    initial_to_final.clear();

    // Fill the map for the next block
    initial_to_final.insert([6u8; 32], ([7u8; 32], 7));
    initial_to_final.insert([7u8; 32], ([8u8; 32], 8));
    initial_to_final.insert([8u8; 32], ([9u8; 32], 9));

    // Now assume on the next block we got 5-6
    let bp5_6 = BatchProofInfo::new([5u8; 32], [6u8; 32], 6);

    recursive_match_state_roots(&mut initial_to_final, &bp5_6);

    assert_eq!(initial_to_final.len(), 1);
    let elem = initial_to_final.get(&[5u8; 32]).unwrap();
    assert_eq!(elem.0, [9u8; 32]);
    // Now the last state root is 9 and last l2 height is 9
}
