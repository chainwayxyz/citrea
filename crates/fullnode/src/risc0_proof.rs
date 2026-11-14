//! Reads RISC0 batch proofs published up to the RISC0 cutoff, without verifying them.
//!
//! Batch provers published bincode encoded `risc0_zkvm::InnerReceipt`s. The types below
//! mirror the serde layout of risc0-zkvm 3.0 receipts down to the journal.
//!
//! The batch prover's DA signature stands in for the seal and image ID. The checks of v2's
//! `Vm::verify` that don't need them stay: only receipts of a successful execution without
//! assumptions are read, and fake receipts only on networks that allowed development mode.

// Fields and variants are documented in risc0-zkvm
#![allow(clippy::missing_docs_in_private_items)]

use borsh::BorshDeserialize;
use serde::Deserialize;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;

/// `risc0_zkvm::sha::Digest`
type Digest = [u32; 8];

/// `risc0_zkvm::MaybePruned`
#[derive(Deserialize)]
enum MaybePruned<T> {
    Value(T),
    Pruned(#[allow(dead_code)] Digest),
}

/// `risc0_zkvm::InnerReceipt`, batch provers publish Groth16 receipts, or fake ones in
/// development mode.
#[derive(Deserialize)]
enum InnerReceipt {
    Composite,
    Succinct,
    Groth16(Box<Groth16Receipt>),
    Fake(Box<FakeReceipt>),
}

/// `risc0_zkvm::FakeReceipt<ReceiptClaim>`
#[derive(Deserialize)]
struct FakeReceipt {
    claim: MaybePruned<ReceiptClaim>,
}

/// `risc0_zkvm::Groth16Receipt<ReceiptClaim>`
#[derive(Deserialize)]
struct Groth16Receipt {
    _seal: Vec<u8>,
    claim: MaybePruned<ReceiptClaim>,
    _verifier_parameters: Digest,
}

/// `risc0_zkvm::ReceiptClaim`
#[derive(Deserialize)]
struct ReceiptClaim {
    _pre: MaybePruned<SystemState>,
    _post: MaybePruned<SystemState>,
    exit_code: ExitCode,
    _input: MaybePruned<Option<Unknown>>,
    output: MaybePruned<Option<Output>>,
}

/// `risc0_zkvm::SystemState`
#[derive(Deserialize)]
struct SystemState {
    _pc: u32,
    _merkle_root: Digest,
}

/// `risc0_zkvm::ExitCode`
#[derive(Deserialize)]
enum ExitCode {
    Halted(u32),
    Paused(#[allow(dead_code)] u32),
    SystemSplit,
    SessionLimit,
}

/// Uninhabited `risc0_zkvm::Input`
#[derive(Deserialize)]
enum Unknown {}

/// `risc0_zkvm::Output`
#[derive(Deserialize)]
struct Output {
    journal: MaybePruned<Vec<u8>>,
    assumptions: MaybePruned<Vec<MaybePruned<Assumption>>>,
}

/// `risc0_zkvm::Assumption`
#[derive(Deserialize)]
struct Assumption {
    _claim: Digest,
    _control_root: Digest,
}

/// Digest of an empty assumptions list, as `risc0_zkvm::ReceiptClaim::ok` prunes it.
const NO_ASSUMPTIONS_DIGEST: Digest = [0; 8];

/// Returns the journal of a serialized RISC0 receipt of a successful execution.
fn extract_journal(proof: &[u8], allow_fake_receipts: bool) -> Option<Vec<u8>> {
    let claim = match bincode::deserialize(proof).ok()? {
        InnerReceipt::Groth16(receipt) => receipt.claim,
        InnerReceipt::Fake(receipt) if allow_fake_receipts => receipt.claim,
        _ => return None,
    };
    let MaybePruned::Value(claim) = claim else {
        return None;
    };
    if !matches!(claim.exit_code, ExitCode::Halted(0)) {
        return None;
    }
    let MaybePruned::Value(Some(output)) = claim.output else {
        return None;
    };
    let no_assumptions = match output.assumptions {
        MaybePruned::Value(assumptions) => assumptions.is_empty(),
        MaybePruned::Pruned(digest) => digest == NO_ASSUMPTIONS_DIGEST,
    };
    if !no_assumptions {
        return None;
    }
    let MaybePruned::Value(journal) = output.journal else {
        return None;
    };
    Some(journal)
}

/// Returns the batch proof output of a serialized RISC0 receipt.
pub(crate) fn extract_batch_proof_output(
    proof: &[u8],
    allow_fake_receipts: bool,
) -> Option<BatchProofCircuitOutput> {
    BatchProofCircuitOutput::try_from_slice(&extract_journal(proof, allow_fake_receipts)?).ok()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;

    use super::*;

    fn sample_output() -> BatchProofCircuitOutput {
        BatchProofCircuitOutput::V3(BatchProofCircuitOutputV3 {
            state_roots: vec![[1; 32], [2; 32], [3; 32]],
            final_l2_block_hash: [4; 32],
            state_diff: BTreeMap::from([
                (b"key".to_vec().into(), Some(b"value".to_vec().into())),
                (b"deleted".to_vec().into(), None),
            ]),
            last_l2_height: 1_234_567,
            sequencer_commitment_hashes: vec![[5; 32], [6; 32]],
            sequencer_commitment_index_range: (41, 42),
            last_l1_hash_on_bitcoin_light_client_contract: [7; 32],
            previous_commitment_index: Some(40),
            previous_commitment_hash: Some([8; 32]),
        })
    }

    /// Size of bincode's enum tag, and of its length prefix of the Groth16 seal.
    const TAG_SIZE: usize = 4;
    const LENGTH_SIZE: usize = 8;
    /// Size of the Groth16 receipt's verifier parameters.
    const VERIFIER_PARAMETERS_SIZE: usize = 32;
    /// Size of the unpruned fixture's assumptions list, with its length prefix.
    const ASSUMPTIONS_SIZE: usize = 112;
    /// Variant index of `InnerReceipt::Fake`.
    const FAKE_TAG: u8 = 3;

    /// Receipts serialized with risc0-zkvm 3.0.6, journal is `sample_output`
    fn fixture(hex: &str) -> Vec<u8> {
        hex::decode(hex.trim()).unwrap()
    }

    /// Fixture with its claim's fields as values. It has two assumptions, which v2 rejected.
    fn unpruned_receipt_with_assumptions() -> Vec<u8> {
        fixture(include_str!(
            "../test_data/risc0-groth16-receipt-unpruned.hex"
        ))
    }

    /// The unpruned fixture with an empty assumptions list.
    fn unpruned_receipt() -> Vec<u8> {
        let receipt = unpruned_receipt_with_assumptions();
        let verifier_parameters = receipt.len() - VERIFIER_PARAMETERS_SIZE;
        [
            &receipt[..verifier_parameters - ASSUMPTIONS_SIZE],
            &[0; LENGTH_SIZE],
            &receipt[verifier_parameters..],
        ]
        .concat()
    }

    #[test]
    fn reads_batch_proof_output_of_risc0_groth16_receipts() {
        let expected = borsh::to_vec(&sample_output()).unwrap();
        for receipt in [
            fixture(include_str!("../test_data/risc0-groth16-receipt.hex")),
            unpruned_receipt(),
        ] {
            for allow_fake_receipts in [false, true] {
                let output = extract_batch_proof_output(&receipt, allow_fake_receipts).unwrap();
                assert_eq!(borsh::to_vec(&output).unwrap(), expected);
            }
        }
    }

    /// Returns the Groth16 receipt's claim bytes.
    fn claim_of(receipt: &[u8]) -> &[u8] {
        let seal_length = u64::from_le_bytes(
            receipt[TAG_SIZE..TAG_SIZE + LENGTH_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;
        &receipt[TAG_SIZE + LENGTH_SIZE + seal_length..receipt.len() - VERIFIER_PARAMETERS_SIZE]
    }

    /// A fake receipt with the claim of the fixture.
    fn fake_receipt(receipt: &[u8]) -> Vec<u8> {
        let mut fake = FAKE_TAG.to_le_bytes().to_vec();
        fake.extend([0; TAG_SIZE - 1]);
        fake.extend(claim_of(receipt));
        fake
    }

    #[test]
    fn reads_fake_receipts_only_when_allowed() {
        let expected = borsh::to_vec(&sample_output()).unwrap();
        for receipt in [
            fixture(include_str!("../test_data/risc0-groth16-receipt.hex")),
            unpruned_receipt(),
        ] {
            let fake = fake_receipt(&receipt);
            let output = extract_batch_proof_output(&fake, true).unwrap();
            assert_eq!(borsh::to_vec(&output).unwrap(), expected);
            assert!(extract_batch_proof_output(&fake, false).is_none());
        }
    }

    /// Fields of a proof published on a network, as `ledger_getVerifiedBatchProofsBySlotHeight`
    /// reports its output.
    struct PublishedProof {
        receipt: &'static str,
        initial_state_root: &'static str,
        final_state_root: &'static str,
        last_l2_height: u64,
        sequencer_commitment_index: u32,
    }

    /// Groth16 proofs published on mainnet. RISC0 pruned different claim fields over time.
    const MAINNET_PROOFS: [PublishedProof; 2] = [
        // L1 block 927009: `pre` is pruned to the image ID, the assumptions to their digest.
        PublishedProof {
            receipt: include_str!("../test_data/risc0-mainnet-groth16-pruned-pre-receipt.hex"),
            initial_state_root: "141aac821009225e779f99d7f23461ad96430d423dc098a4b15495e60bcc78a0",
            final_state_root: "fceaf646f3174add824963f6b4be1d278e63304b10b33c9e566e7923b54d2a3f",
            last_l2_height: 553_000,
            sequencer_commitment_index: 553,
        },
        // L1 block 963000: `pre` and the assumptions are values, `input` is pruned.
        PublishedProof {
            receipt: include_str!("../test_data/risc0-mainnet-groth16-receipt.hex"),
            initial_state_root: "da7630c24f1725c2409350e5cb4b9fb7f0fd1d955a61fc7d242dbbb0d6f5d5b0",
            final_state_root: "19ed1c724946256b8ffed4c38685acfde33e1fc708f133b48f27c6bf33f2302b",
            last_l2_height: 11_464_000,
            sequencer_commitment_index: 11464,
        },
    ];

    /// Fake proof published on testnet, at L1 block 159133.
    const TESTNET_PROOF: PublishedProof = PublishedProof {
        receipt: include_str!("../test_data/risc0-testnet-fake-receipt.hex"),
        initial_state_root: "d0af5add26f1af6b5226eb6ee3187438a8a7479f41b52ab45d571b598d1fe24c",
        final_state_root: "cdf6305a555cf1328074c4e71dbd7cfa08c0b4ebbc19032708f44864fb8875f3",
        last_l2_height: 33_510_925,
        sequencer_commitment_index: 26236,
    };

    fn assert_reads_published_proof(proof: &PublishedProof, allow_fake_receipts: bool) {
        let output =
            extract_batch_proof_output(&fixture(proof.receipt), allow_fake_receipts).unwrap();
        assert_eq!(
            hex::encode(output.initial_state_root()),
            proof.initial_state_root
        );
        assert_eq!(
            hex::encode(output.final_state_root()),
            proof.final_state_root
        );
        assert_eq!(output.last_l2_height(), proof.last_l2_height);
        assert_eq!(
            output.sequencer_commitment_index_range(),
            (
                proof.sequencer_commitment_index,
                proof.sequencer_commitment_index
            )
        );
    }

    /// Mainnet doesn't allow development mode, and its Groth16 proofs don't need it.
    #[test]
    fn reads_groth16_proofs_published_on_mainnet() {
        for proof in &MAINNET_PROOFS {
            assert_reads_published_proof(proof, false);
        }
    }

    /// Testnet's fake proofs are only read on networks that allow development mode.
    #[test]
    fn reads_fake_proofs_published_on_testnet_only_when_allowed() {
        assert_reads_published_proof(&TESTNET_PROOF, true);
        assert!(extract_batch_proof_output(&fixture(TESTNET_PROOF.receipt), false).is_none());
    }

    #[test]
    fn rejects_unsuccessful_executions_and_assumptions() {
        let receipt = fixture(include_str!("../test_data/risc0-groth16-receipt.hex"));
        let fake = fake_receipt(&receipt);
        // The receipt's and the claim's tags, `pre`'s tag and digest, `post`'s tag, pc and root
        let exit_code = TAG_SIZE + TAG_SIZE + (TAG_SIZE + 32) + (TAG_SIZE + 4 + 32);
        // `ExitCode::Halted` is variant 0, then its u32
        assert_eq!(fake[exit_code..exit_code + 8], [0; 8]);

        let mut non_zero_exit = fake.clone();
        non_zero_exit[exit_code + TAG_SIZE] = 1;
        assert!(extract_batch_proof_output(&non_zero_exit, true).is_none());

        // `ExitCode::Paused` is variant 1
        let mut paused = fake.clone();
        paused[exit_code] = 1;
        assert!(extract_batch_proof_output(&paused, true).is_none());

        // The pruned assumptions are the last field of the claim
        let mut with_assumptions = fake.clone();
        let digest = with_assumptions.len() - 32;
        with_assumptions[digest] = 1;
        assert!(extract_batch_proof_output(&with_assumptions, true).is_none());

        assert!(extract_batch_proof_output(&unpruned_receipt_with_assumptions(), true).is_none());
    }

    /// After L0, the SP1 light client keeps P0's RISC0 batch proof method IDs until the security
    /// council adds the SP1 key, and the full node verifies with SP1. RISC0 proving stops at P0,
    /// but neither could accept a RISC0 receipt published later, under any key or in development
    /// mode: it isn't an SP1 proof envelope, which both decode before selecting a key.
    #[test]
    fn risc0_receipts_are_not_sp1_proofs() {
        use sov_rollup_interface::zk::sp1::SP1Proof;

        for receipt in [
            fixture(include_str!("../test_data/risc0-groth16-receipt.hex")),
            unpruned_receipt(),
        ] {
            assert!(extract_batch_proof_output(&receipt, false).is_some());
            assert!(SP1Proof::try_from_slice(&receipt).is_err());
        }
        for proof in MAINNET_PROOFS.iter().chain([&TESTNET_PROOF]) {
            assert!(SP1Proof::try_from_slice(&fixture(proof.receipt)).is_err());
        }
    }

    #[test]
    fn rejects_other_proofs() {
        let receipt = fixture(include_str!("../test_data/risc0-groth16-receipt.hex"));
        assert!(extract_batch_proof_output(&receipt[..receipt.len() - 1], true).is_none());

        // A Groth16 receipt's bytes are not a fake receipt
        let mut fake = receipt.clone();
        fake[0] = FAKE_TAG;
        assert!(extract_batch_proof_output(&fake, true).is_none());

        let sp1_proof = borsh::to_vec(&sov_rollup_interface::zk::sp1::SP1Proof::Mock {
            program: [0; 8],
            public_values: borsh::to_vec(&sample_output()).unwrap(),
        })
        .unwrap();
        assert!(extract_batch_proof_output(&sp1_proof, true).is_none());
    }
}
