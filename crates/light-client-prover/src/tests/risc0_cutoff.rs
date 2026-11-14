//! The SP1 light client of a network proven with RISC0 continues from P0, the RISC0 light client
//! proof output at L0. Its first proof, at L0 + 1, has no previous proof, and the guest uses P0,
//! compiled in as the network's [`Risc0Cutoff`], as the previous output. From there it is the
//! ordinary continuation of a light client chain:
//! - L0 + 1's header is verified against P0's DA state, so no other L1 block can start from P0.
//! - The JMT is P0's, with the commitments, proven state transitions and L1 hashes the RISC0
//!   light client saw up to L0.
//! - The batch proof method IDs are P0's RISC0 ones, until the security council adds the SP1
//!   batch key, with the specified activation height `P0.last_l2_height`.
//!
//! Every L1 block runs natively, like in the light client prover's input builder, then in the
//! guest on the native witness, through `run_circuit`'s code path with the given cutoff. Both
//! must agree. [`MockZkGuest`] verifies mock proofs by program. RISC0 proving stops at P0, and a
//! RISC0 receipt published after L0 anyway is an invalid proof here: SP1 can't parse it, see
//! `citrea_fullnode::risc0_proof`.

use std::ops::RangeInclusive;
use std::panic::{catch_unwind, AssertUnwindSafe};

use borsh::{BorshDeserialize, BorshSerialize};
use citrea_primitives::risc0_cutoff::Risc0Cutoff;
use sov_mock_da::{MockBlob, MockBlockHeader, MockDaSpec, MockDaVerifier, MockHash};
use sov_mock_zkvm::MockZkGuest;
use sov_modules_api::WorkingSet;
use sov_rollup_interface::da::{DaVerifier, SequencerCommitment};
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use sov_rollup_interface::Network;
use sov_state::{ProverStorage, ZkStorage};
use tempfile::{tempdir, TempDir};

use super::test_utils::{
    create_mock_batch_proof_of_program, create_mock_sequencer_commitment,
    create_mock_sequencer_commitment_blob, create_new_method_id_tx, create_prev_lcp_serialized,
    NativeCircuitRunner, NativeL1BlockResult,
};
use crate::circuit::accessors::{
    BatchProofMethodIdAccessor, BlockHashAccessor, SequencerCommitmentAccessor,
    VerifiedStateTransitionForSequencerCommitmentIndexAccessor,
};
use crate::circuit::initial_values::mockda::METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEYS;
use crate::circuit::{LightClientProofCircuit, LightClientVerificationError};

/// Batch proof method ID of the RISC0 batch program.
const RISC0_BATCH_PROOF_METHOD_ID: [u32; 8] = [7; 8];
/// Batch proof method ID of the SP1 batch program.
const SP1_BATCH_PROOF_METHOD_ID: [u32; 8] = [8; 8];
/// Light client proof method ID of the RISC0 light client, the one in P0.
const RISC0_LIGHT_CLIENT_PROOF_METHOD_ID: [u32; 8] = [2; 8];
/// Light client proof method ID of the SP1 light client.
const SP1_LIGHT_CLIENT_PROOF_METHOD_ID: [u32; 8] = [1; 8];
/// DA public key of the batch prover, v2 and v3 alike.
const BATCH_PROVER_DA_PUB_KEY: [u8; 32] = [9; 32];
/// DA public key of the sequencer, the sender of [`create_mock_sequencer_commitment_blob`].
const SEQUENCER_DA_PUB_KEY: [u8; 32] = [45; 32];
/// Security council transactions are authorized by their signatures, not by their sender.
const SECURITY_COUNCIL_TX_SENDER: [u8; 32] = [3; 32];
/// L2 genesis state root of the network.
const L2_GENESIS_ROOT: [u8; 32] = [1; 32];
/// L0, the L1 block of P0.
const L0: u64 = 2;

/// A light client guest: its method ID, the values it is compiled with, and its RISC0 cutoff.
#[derive(Clone)]
struct Guest {
    light_client_proof_method_id: [u32; 8],
    l2_genesis_root: [u8; 32],
    initial_batch_proof_method_ids: Vec<(u64, [u32; 8])>,
    risc0_cutoff: Option<Risc0Cutoff>,
}

impl Guest {
    /// The RISC0 light client that proved the network from genesis up to L0.
    fn risc0() -> Self {
        Self {
            light_client_proof_method_id: RISC0_LIGHT_CLIENT_PROOF_METHOD_ID,
            l2_genesis_root: L2_GENESIS_ROOT,
            initial_batch_proof_method_ids: vec![(0, RISC0_BATCH_PROOF_METHOD_ID)],
            risc0_cutoff: None,
        }
    }

    /// The SP1 light client compiled with the cutoff. A light client continuing from P0 never
    /// uses its initial batch proof method IDs.
    fn sp1(cutoff: Risc0Cutoff) -> Self {
        Self {
            light_client_proof_method_id: SP1_LIGHT_CLIENT_PROOF_METHOD_ID,
            l2_genesis_root: L2_GENESIS_ROOT,
            initial_batch_proof_method_ids: vec![(0, SP1_BATCH_PROOF_METHOD_ID)],
            risc0_cutoff: Some(cutoff),
        }
    }

    fn input(
        &self,
        header: MockBlockHeader,
        previous: Option<&LightClientCircuitOutput>,
        blobs: Vec<MockBlob>,
    ) -> LightClientCircuitInput<MockDaSpec> {
        LightClientCircuitInput {
            previous_light_client_proof: previous
                .map(|output| create_prev_lcp_serialized(output.clone(), true)),
            light_client_proof_method_id: self.light_client_proof_method_id,
            da_block_header: header,
            inclusion_proof: [1; 32],
            completeness_proof: blobs,
            witness: Default::default(),
        }
    }

    /// Runs an L1 block natively and commits its JMT changes, returning the input with its witness.
    fn run_natively(
        &self,
        native: &NativeCircuitRunner,
        input: LightClientCircuitInput<MockDaSpec>,
    ) -> (LightClientCircuitInput<MockDaSpec>, NativeL1BlockResult) {
        native.run_with_risc0_cutoff(
            input,
            self.l2_genesis_root,
            self.initial_batch_proof_method_ids.clone(),
            &BATCH_PROVER_DA_PUB_KEY,
            &SEQUENCER_DA_PUB_KEY,
            &METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEYS,
            Network::Nightly,
            self.risc0_cutoff.clone(),
        )
    }

    /// Runs the guest on an input, as `run_circuit` does with the guest's compiled cutoff.
    fn run_in_guest(
        &self,
        input: LightClientCircuitInput<MockDaSpec>,
    ) -> Result<LightClientCircuitOutput, LightClientVerificationError<MockDaVerifier>> {
        LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new().run_circuit(
            MockDaVerifier {},
            input,
            ZkStorage::new(),
            Network::Nightly,
            self.risc0_cutoff.clone(),
            self.l2_genesis_root,
            self.initial_batch_proof_method_ids.clone(),
            &BATCH_PROVER_DA_PUB_KEY,
            &SEQUENCER_DA_PUB_KEY,
            &METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEYS,
        )
    }

    /// Proves an L1 block: runs it natively, then in the guest, and checks that they agree.
    fn prove(
        &self,
        native: &NativeCircuitRunner,
        header: MockBlockHeader,
        previous: Option<&LightClientCircuitOutput>,
        blobs: Vec<MockBlob>,
    ) -> LightClientCircuitOutput {
        let height = header.height;
        let (input, native_result) = self.run_natively(native, self.input(header, previous, blobs));
        let output = self.run_in_guest(input).unwrap();
        assert_eq!(
            native_result,
            native_result_of(&output),
            "Native and guest execution of L1 block {height} must agree"
        );
        output
    }
}

fn native_result_of(output: &LightClientCircuitOutput) -> NativeL1BlockResult {
    NativeL1BlockResult {
        l2_state_root: output.l2_state_root,
        lcp_state_root: output.lcp_state_root,
        last_l2_height: output.last_l2_height,
        last_sequencer_commitment_index: output.last_sequencer_commitment_index,
    }
}

fn header(height: u64) -> MockBlockHeader {
    MockBlockHeader::from_height(height)
}

fn hash(height: u64) -> [u8; 32] {
    header(height).hash.0
}

/// L2 state of a light client proof output: state root, last L2 height and commitment index.
fn l2(output: &LightClientCircuitOutput) -> ([u8; 32], u64, u32) {
    (
        output.l2_state_root,
        output.last_l2_height,
        output.last_sequencer_commitment_index,
    )
}

/// The cutoff of P0: every field of the RISC0 output except its light client method ID.
fn cutoff_of(p0: &LightClientCircuitOutput) -> Risc0Cutoff {
    Risc0Cutoff {
        da_state: p0.latest_da_state.clone(),
        l2_state_root: p0.l2_state_root,
        last_l2_height: p0.last_l2_height,
        last_sequencer_commitment_index: p0.last_sequencer_commitment_index,
        lc_state_root: p0.lcp_state_root,
    }
}

fn copy<T: BorshSerialize + BorshDeserialize>(value: &T) -> T {
    borsh::from_slice(&borsh::to_vec(value).unwrap()).unwrap()
}

/// The RISC0 light client chain up to L0, with a native runner holding its JMT.
///
/// Commitment `i` ends at L2 height `i + 1` with state root `[i + 1; 32]`. Commitments 1 to 3
/// are posted up to L0, and RISC0 proves 1 and 2, so P0 ends at commitment 2 and L2 height 3,
/// with commitment 3 pending. The tests post commitments 4 and 5 after L0.
struct Risc0Chain {
    native: NativeCircuitRunner,
    commitments: Vec<SequencerCommitment>,
    p0: LightClientCircuitOutput,
    sp1: Guest,
    _db_dir: TempDir,
}

fn risc0_chain() -> Risc0Chain {
    let db_dir = tempdir().unwrap();
    let native = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let commitments: Vec<_> = (1..=5)
        .map(|index| {
            create_mock_sequencer_commitment(index, index as u64 + 1, [index as u8 + 1; 32])
        })
        .collect();
    let risc0 = Guest::risc0();

    let output_1 = risc0.prove(
        &native,
        header(1),
        None,
        vec![
            commitment(&commitments, 1),
            commitment(&commitments, 2),
            batch_proof(RISC0_BATCH_PROOF_METHOD_ID, &commitments, 1..=1, hash(1)),
        ],
    );
    let p0 = risc0.prove(
        &native,
        header(L0),
        Some(&output_1),
        vec![
            commitment(&commitments, 3),
            batch_proof(RISC0_BATCH_PROOF_METHOD_ID, &commitments, 2..=2, hash(L0)),
        ],
    );
    assert_eq!(l2(&p0), ([3; 32], 3, 2));
    assert_eq!(p0.latest_da_state.block_height, L0);
    assert_eq!(
        p0.light_client_proof_method_id,
        RISC0_LIGHT_CLIENT_PROOF_METHOD_ID
    );

    Risc0Chain {
        native,
        sp1: Guest::sp1(cutoff_of(&p0)),
        commitments,
        p0,
        _db_dir: db_dir,
    }
}

fn commitment(commitments: &[SequencerCommitment], index: u32) -> MockBlob {
    create_mock_sequencer_commitment_blob(commitments[index as usize - 1].clone())
}

/// A batch proof by `program` of the commitments in `range`, built on the commitment before.
fn batch_proof(
    program: [u32; 8],
    commitments: &[SequencerCommitment],
    range: RangeInclusive<u32>,
    last_l1_hash_on_bitcoin_light_client_contract: [u8; 32],
) -> MockBlob {
    proof_blob(
        program,
        true,
        commitments,
        range,
        last_l1_hash_on_bitcoin_light_client_contract,
    )
}

/// A RISC0 receipt published after L0, although RISC0 proving stops at P0. SP1 can't verify it
/// under any key, so it is an invalid proof of the RISC0 program here.
fn risc0_receipt(
    commitments: &[SequencerCommitment],
    range: RangeInclusive<u32>,
    last_l1_hash_on_bitcoin_light_client_contract: [u8; 32],
) -> MockBlob {
    proof_blob(
        RISC0_BATCH_PROOF_METHOD_ID,
        false,
        commitments,
        range,
        last_l1_hash_on_bitcoin_light_client_contract,
    )
}

fn proof_blob(
    program: [u32; 8],
    is_valid: bool,
    commitments: &[SequencerCommitment],
    range: RangeInclusive<u32>,
    last_l1_hash_on_bitcoin_light_client_contract: [u8; 32],
) -> MockBlob {
    let first = *range.start();
    let proven: Vec<_> = range
        .map(|index| commitments[index as usize - 1].clone())
        .collect();
    let previous = (first > 1).then(|| &commitments[first as usize - 2]);
    create_mock_batch_proof_of_program(
        program,
        previous.map_or(L2_GENESIS_ROOT, |c| c.merkle_root),
        proven.last().unwrap().l2_end_block_number,
        is_valid,
        last_l1_hash_on_bitcoin_light_client_contract,
        proven,
        previous.map(|c| c.serialize_and_calculate_sha_256()),
        BATCH_PROVER_DA_PUB_KEY,
    )
}

/// The security council transaction that adds the SP1 batch key.
fn sp1_method_id_tx(activation_l2_height: u64) -> MockBlob {
    create_new_method_id_tx(
        activation_l2_height,
        SP1_BATCH_PROOF_METHOD_ID,
        SECURITY_COUNCIL_TX_SENDER,
        Network::Nightly,
    )
}

fn assert_panics<T>(f: impl FnOnce() -> T, expected: &str) {
    let payload = catch_unwind(AssertUnwindSafe(f))
        .err()
        .unwrap_or_else(|| panic!("Must panic with {expected:?}"));
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .expect("Panic must have a diagnostic");
    assert!(
        message.contains(expected),
        "Expected a panic with {expected:?}, got {message:?}"
    );
}

fn assert_header_chain_rejected(
    result: Result<LightClientCircuitOutput, LightClientVerificationError<MockDaVerifier>>,
    expected: &str,
) {
    match result {
        Err(LightClientVerificationError::HeaderChainVerificationFailed(error)) => assert!(
            error.to_string().contains(expected),
            "Expected {expected:?}, got {error}"
        ),
        other => panic!("Expected a header chain verification failure, got {other:?}"),
    }
}

/// The first SP1 light client proof, at L0 + 1, has no previous proof and continues from P0:
/// P0's L2 state, DA state and JMT, with the SP1 light client's method ID. The SP1 guest's
/// genesis values are not used, and P0's JMT keeps the RISC0 batch proof method IDs.
#[test]
fn first_sp1_light_client_proof_continues_from_p0() {
    let Risc0Chain {
        native,
        commitments,
        p0,
        sp1,
        _db_dir,
    } = risc0_chain();

    let (input, native_result) = sp1.run_natively(
        &native,
        sp1.input(header(L0 + 1), None, vec![commitment(&commitments, 4)]),
    );
    assert!(input.previous_light_client_proof.is_none());
    let output = sp1.run_in_guest(copy(&input)).unwrap();
    assert_eq!(native_result, native_result_of(&output));

    assert_eq!(l2(&output), l2(&p0), "L2 stays at P0 without SP1 proofs");
    assert_eq!(
        output.latest_da_state,
        MockDaVerifier {}
            .verify_header_chain(Some(&p0.latest_da_state), &header(L0 + 1), Network::Nightly)
            .unwrap(),
        "L0 + 1 is verified against P0's DA state"
    );
    assert_eq!(output.latest_da_state.block_height, L0 + 1);
    assert_eq!(
        output.light_client_proof_method_id, SP1_LIGHT_CLIENT_PROOF_METHOD_ID,
        "The SP1 light client commits to its own method ID, not P0's"
    );
    assert_ne!(output.lcp_state_root, p0.lcp_state_root);

    // The guest's genesis values are not used
    let other_genesis = Guest {
        l2_genesis_root: [0xee; 32],
        initial_batch_proof_method_ids: vec![(0, [0xee; 8])],
        ..sp1.clone()
    };
    assert_eq!(other_genesis.run_in_guest(input).unwrap(), output);

    // P0's JMT: the RISC0 method IDs, the commitments, the state transitions proven by RISC0,
    // and the L1 hashes up to L0, then L0 + 1's
    let mut working_set =
        WorkingSet::new(native.prover_storage_manager.create_final_view_storage());
    assert_eq!(
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap(),
        vec![(0, RISC0_BATCH_PROOF_METHOD_ID)]
    );
    for index in 1..=4 {
        assert_eq!(
            SequencerCommitmentAccessor::<ProverStorage>::get(index, &mut working_set).as_ref(),
            Some(&commitments[index as usize - 1])
        );
    }
    for index in 1..=3 {
        assert_eq!(
            VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::get(
                index,
                &mut working_set
            )
            .is_some(),
            index <= p0.last_sequencer_commitment_index
        );
    }
    for height in 1..=L0 + 1 {
        assert!(BlockHashAccessor::<ProverStorage>::exists(
            hash(height),
            &mut working_set
        ));
    }
}

/// An SP1 light client starting with an empty JMT at L0 + 1 would not know the L1 hashes up to
/// L0, so it would reject the batch proofs that refer to them. P0's JMT knows them: the first
/// SP1 batch proof refers to L1 block 1, before L0, and is accepted. An L1 hash the light client
/// has never seen is still rejected.
#[test]
fn sp1_batch_proofs_can_refer_to_l1_blocks_up_to_l0() {
    for (last_l1_hash, expected) in [
        (hash(1), ([4; 32], 4, 3)),
        (hash(L0), ([4; 32], 4, 3)),
        (hash(L0 + 1), ([4; 32], 4, 3)),
        (hash(42), ([3; 32], 3, 2)),
    ] {
        let Risc0Chain {
            native,
            commitments,
            p0,
            sp1,
            _db_dir,
        } = risc0_chain();
        let output = sp1.prove(
            &native,
            header(L0 + 1),
            None,
            vec![
                sp1_method_id_tx(p0.last_l2_height),
                batch_proof(SP1_BATCH_PROOF_METHOD_ID, &commitments, 3..=3, last_l1_hash),
            ],
        );
        assert_eq!(l2(&output), expected, "{last_l1_hash:?}");
    }
}

/// RISC0 proving stops at P0, but RISC0 receipts published after L0 from the same DA key anyway
/// must not break the SP1 chain. Before the security council transaction, SP1 can't verify
/// them. After it, the SP1 key is selected after P0, so even a valid proof of the RISC0 program
/// is rejected. Neither stalls the SP1 proofs, a proof ending at P0 is a replay, and no
/// commitment is counted twice.
#[test]
fn risc0_proofs_are_never_accepted_after_l0() {
    let Risc0Chain {
        native,
        commitments,
        p0,
        sp1,
        _db_dir,
    } = risc0_chain();

    let first = sp1.prove(
        &native,
        header(L0 + 1),
        None,
        vec![
            risc0_receipt(&commitments, 3..=3, hash(L0 + 1)),
            commitment(&commitments, 4),
        ],
    );
    assert_eq!(l2(&first), l2(&p0));

    let second = sp1.prove(
        &native,
        header(L0 + 2),
        Some(&first),
        vec![
            sp1_method_id_tx(p0.last_l2_height),
            batch_proof(
                RISC0_BATCH_PROOF_METHOD_ID,
                &commitments,
                3..=3,
                hash(L0 + 2),
            ),
            risc0_receipt(&commitments, 3..=4, hash(L0 + 2)),
            batch_proof(SP1_BATCH_PROOF_METHOD_ID, &commitments, 2..=2, hash(L0)),
        ],
    );
    assert_eq!(l2(&second), l2(&p0));

    let third = sp1.prove(
        &native,
        header(L0 + 3),
        Some(&second),
        vec![
            batch_proof(SP1_BATCH_PROOF_METHOD_ID, &commitments, 3..=3, hash(L0)),
            batch_proof(
                RISC0_BATCH_PROOF_METHOD_ID,
                &commitments,
                4..=4,
                hash(L0 + 3),
            ),
        ],
    );
    assert_eq!(l2(&third), ([4; 32], 4, 3));

    let fourth = sp1.prove(
        &native,
        header(L0 + 4),
        Some(&third),
        vec![
            commitment(&commitments, 5),
            batch_proof(SP1_BATCH_PROOF_METHOD_ID, &commitments, 3..=3, hash(L0)),
            batch_proof(SP1_BATCH_PROOF_METHOD_ID, &commitments, 4..=4, hash(L0 + 3)),
            risc0_receipt(&commitments, 5..=5, hash(L0 + 4)),
        ],
    );
    assert_eq!(l2(&fourth), ([5; 32], 5, 4));
    let mut working_set =
        WorkingSet::new(native.prover_storage_manager.create_final_view_storage());
    assert!(
        VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::get(
            5,
            &mut working_set
        )
        .is_none()
    );
}

/// The guest uses P0 for every missing previous proof, so a prover may omit the previous proof
/// of any L1 block. P0's DA state only accepts L0 + 1, the child of L0: every other block fails
/// header chain verification, so the SP1 light client chain has a single start.
#[test]
fn only_l0_plus_one_can_omit_the_previous_proof() {
    let Risc0Chain {
        native,
        sp1,
        _db_dir,
        ..
    } = risc0_chain();
    let fork_of_l0_plus_one = MockBlockHeader {
        prev_hash: MockHash([0xf0; 32]),
        hash: MockHash([0xf1; 32]),
        ..header(L0 + 1)
    };
    for (block, expected) in [
        (header(L0 - 1), "Block heights are not consecutive"),
        (header(L0), "Block heights are not consecutive"),
        (header(L0 + 2), "Block heights are not consecutive"),
        (header(L0 + 3), "Block heights are not consecutive"),
        (fork_of_l0_plus_one, "Block prev hash does not match"),
    ] {
        assert_header_chain_rejected(sp1.run_in_guest(sp1.input(block, None, vec![])), expected);
    }

    // The chain continues by recursion, and still can't restart from P0 later
    let first = sp1.prove(&native, header(L0 + 1), None, vec![]);
    let second = sp1.prove(&native, header(L0 + 2), Some(&first), vec![]);
    assert_header_chain_rejected(
        sp1.run_in_guest(sp1.input(header(L0 + 3), None, vec![])),
        "Block heights are not consecutive",
    );
    let third = sp1.prove(&native, header(L0 + 3), Some(&second), vec![]);
    assert_eq!(third.latest_da_state.block_height, L0 + 3);
    assert_eq!(
        third.light_client_proof_method_id,
        SP1_LIGHT_CLIENT_PROOF_METHOD_ID
    );

    // A next proof must verify its previous proof with the method ID the chain started with
    let other_method_id = Guest {
        light_client_proof_method_id: [5; 8],
        ..sp1.clone()
    };
    let input = other_method_id.input(header(L0 + 4), Some(&third), vec![]);
    assert_panics(
        || other_method_id.run_in_guest(input),
        "Previous light client proof is invalid",
    );
}
