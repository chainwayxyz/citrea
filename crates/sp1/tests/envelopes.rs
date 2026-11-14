//! SP1 proof transport with native program digests.

use citrea_sp1::guest::SP1Guest;
use citrea_sp1::{ProgramVKeyHash, SP1Proof};
use sov_rollup_interface::zk::compressed::CompressedProof;
use sov_rollup_interface::zk::sp1::KOALABEAR_P;
use sov_rollup_interface::zk::Zkvm;

const PROGRAM: ProgramVKeyHash = [1, 2, 3, 4, 5, 6, 7, 8];

fn groth16() -> SP1Proof {
    SP1Proof::Groth16 {
        proof: vec![9; 356],
        public_values: borsh::to_vec(&42u64).unwrap(),
    }
}

fn mock() -> SP1Proof {
    SP1Proof::Mock {
        program: PROGRAM,
        public_values: borsh::to_vec(&42u64).unwrap(),
    }
}

fn compressed() -> SP1Proof {
    SP1Proof::Compressed {
        proof: CompressedProof {
            native_vkey: PROGRAM,
            proof: vec![10],
            vkey: vec![11],
        },
        public_values: borsh::to_vec(&42u64).unwrap(),
    }
}

#[test]
fn wire_layout_encodes_native_program_digests() {
    // The native SP1 key digest is encoded as eight little-endian u32 words.
    let journal = [8, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0];
    let mut expected = vec![0, 100, 1, 0, 0];
    expected.extend([9; 356]);
    expected.extend(journal);
    assert_eq!(borsh::to_vec(&groth16()).unwrap(), expected);

    let mut expected = vec![1];
    expected.extend(PROGRAM.iter().flat_map(|word| word.to_le_bytes()));
    expected.extend(journal);
    assert_eq!(borsh::to_vec(&mock()).unwrap(), expected);

    let mut expected = vec![3];
    expected.extend(PROGRAM.iter().flat_map(|word| word.to_le_bytes()));
    expected.extend([1, 0, 0, 0, 10, 1, 0, 0, 0, 11]);
    expected.extend(journal);
    assert_eq!(borsh::to_vec(&compressed()).unwrap(), expected);
}

#[test]
fn mock_verification_uses_the_native_program_digest() {
    assert!(mock().verify(&PROGRAM, true).is_ok());
    assert!(mock().verify(&PROGRAM, false).is_err());
    let mut other = PROGRAM;
    other[0] += 1;
    assert!(mock().verify(&other, true).is_err());
    let mut noncanonical = PROGRAM;
    noncanonical[0] = KOALABEAR_P;
    let proof = SP1Proof::Mock {
        program: noncanonical,
        public_values: vec![],
    };
    assert!(proof.verify(&noncanonical, true).is_err());
}

#[test]
fn batch_output_is_deserialized_only_after_verification() {
    let encoded = borsh::to_vec(&mock()).unwrap();
    assert_eq!(
        SP1Guest::verify_and_deserialize_output::<u64>(&encoded, &PROGRAM, true).unwrap(),
        42
    );
    assert!(SP1Guest::verify_and_deserialize_output::<u64>(&encoded, &PROGRAM, false).is_err());
    assert!(SP1Guest::verify_and_deserialize_output::<u64>(&encoded, &[0; 8], true).is_err());

    // Both entry points must reject a recursion claim before it can register an obligation.
    for proof in [compressed(), compressed().guest_hint()] {
        let encoded = borsh::to_vec(&proof).unwrap();
        assert!(SP1Guest::verify(&encoded, &PROGRAM, true).is_err());
        assert!(
            SP1Guest::verify_and_deserialize_output::<u64>(&encoded, &PROGRAM, true)
                .unwrap_err()
                .to_string()
                .contains("Batch proof must be Groth16")
        );
    }
    let encoded = borsh::to_vec(&groth16()).unwrap();
    assert!(SP1Guest::verify_and_deserialize_output::<u64>(&encoded, &PROGRAM, true).is_err());

    let mut invalid_output = mock();
    if let SP1Proof::Mock { public_values, .. } = &mut invalid_output {
        public_values.push(0);
    }
    let encoded = borsh::to_vec(&invalid_output).unwrap();
    assert!(SP1Guest::verify_and_deserialize_output::<u64>(&encoded, &PROGRAM, true).is_err());
}

#[test]
fn lcp_accepts_only_compressed_or_allowed_mock_proofs() {
    assert!(mock().verify_lcp(&PROGRAM, true).is_ok());
    assert!(mock().verify_lcp(&PROGRAM, false).is_err());
    assert!(groth16()
        .verify_lcp(&PROGRAM, true)
        .unwrap_err()
        .to_string()
        .contains("compressed"));

    // The guest hint keeps the claim and strips the host-only proof payload.
    let SP1Proof::Compressed {
        proof,
        public_values,
    } = compressed().guest_hint()
    else {
        panic!("guest hint must stay compressed")
    };
    assert_eq!(proof.native_vkey, PROGRAM);
    assert!(proof.proof.is_empty() && proof.vkey.is_empty());
    assert_eq!(public_values, borsh::to_vec(&42u64).unwrap());
}
