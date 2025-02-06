use sov_rollup_interface::zk::light_client_proof::output::BatchProofInfo;

pub(crate) fn recursive_match_state_roots(
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

pub(crate) fn collect_unchained_outputs(
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

#[cfg(test)]
mod tests {
    use super::*;

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
        if let Some((final_root, last_l2)) = initial_to_final.remove(&bp_info_prev.final_state_root)
        {
            last_l2_height = last_l2;
            last_state_root = final_root;
        }

        assert_eq!(last_l2_height, 2);
        assert_eq!(last_state_root, [2u8; 32]);

        let unchained_outputs = collect_unchained_outputs(&initial_to_final, last_l2_height);
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
        let res = collect_unchained_outputs(&initial_to_final, 5);
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
}
