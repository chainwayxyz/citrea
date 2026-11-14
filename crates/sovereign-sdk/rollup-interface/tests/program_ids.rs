//! Program-key encodings shared by the guests, the node, and the guest build.
use borsh::BorshDeserialize;
use sov_rollup_interface::da::BatchProofMethodIdBody;
use sov_rollup_interface::zk::sp1::{groth16_program_id, ProgramVKeyHash, KOALABEAR_P};

/// Independent decoder of `cargo prove vkey` output.
#[allow(dead_code)]
mod guest_build {
    use std::env;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    include!("../../../../guests/sp1/build_guest.rs");
}

const PROGRAM: ProgramVKeyHash = [1, 2, 3, 4, 5, 6, 7, 8];

/// SP1 6.10.0 mainnet batch-proof key: `HashableKey::hash_u32()` and `cargo prove vkey`.
const SP1_HASH_U32: ProgramVKeyHash = [
    1530400864, 466073203, 630440642, 686503686, 2091131018, 110139638, 2113215428, 700831858,
];
const SP1_CLI_KEY: &str = "0x00b67020c06f1ed9cd2c9e16128eb3706f94841141a4263dbefa8de229c5d872";

#[test]
fn program_ids_match_sp1_key_encodings() {
    assert_eq!(guest_build::native_program_id(SP1_CLI_KEY), SP1_HASH_U32);
    assert_eq!(
        format!(
            "0x{}",
            hex::encode(groth16_program_id(&SP1_HASH_U32).unwrap())
        ),
        SP1_CLI_KEY
    );
}

#[test]
fn cli_decoder_inverts_groth16_packing_for_every_bit() {
    assert_eq!(groth16_program_id(&[0; 8]).unwrap(), [0; 32]);
    assert_eq!(
        guest_build::native_program_id(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ),
        [0; 8]
    );
    for i in 0..8 {
        for bit in 0..31 {
            let mut words = [0; 8];
            words[i] = 1 << bit;
            let key = format!("0x{}", hex::encode(groth16_program_id(&words).unwrap()));
            assert_eq!(guest_build::native_program_id(&key), words);
        }
    }
    let max = [KOALABEAR_P - 1; 8];
    let key = format!("0x{}", hex::encode(groth16_program_id(&max).unwrap()));
    assert_eq!(guest_build::native_program_id(&key), max);
    for i in 0..8 {
        for invalid in [KOALABEAR_P, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let mut words = PROGRAM;
            words[i] = invalid;
            assert!(groth16_program_id(&words).is_err());
        }
    }
}

#[test]
#[should_panic(expected = "Noncanonical SP1 program key")]
fn cli_decoder_rejects_noncanonical_words() {
    guest_build::native_program_id(
        "0x000000000000000000000000000000000000000000000000000000007f000001",
    );
}

#[test]
#[should_panic(expected = "SP1 program key exceeds 248 bits")]
fn cli_decoder_rejects_excess_bits() {
    guest_build::native_program_id(
        "0x0100000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn method_id_updates_encode_native_words_without_bn254_packing() {
    let body = BatchProofMethodIdBody {
        method_id: PROGRAM,
        activation_l2_height: 42,
        chain_id: 7,
    };
    let encoded = borsh::to_vec(&body).unwrap();
    assert_eq!(&encoded[..32], borsh::to_vec(&PROGRAM).unwrap());
    assert_eq!(
        BatchProofMethodIdBody::try_from_slice(&encoded).unwrap(),
        body
    );
}

#[cfg(feature = "native")]
#[test]
fn rpc_method_ids_use_borsh_byte_layout() {
    use sov_rollup_interface::rpc::BatchProofMethodIdRpcResponse;
    let response = BatchProofMethodIdRpcResponse {
        height: alloy_primitives::U64::from(42),
        method_id: PROGRAM,
    };
    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(
        json["methodId"],
        serde_json::json!("0x0100000002000000030000000400000005000000060000000700000008000000")
    );
    // The RPC hex is exactly the method ID bytes of a signed DA method-ID update body.
    let body = BatchProofMethodIdBody {
        method_id: PROGRAM,
        activation_l2_height: 42,
        chain_id: 7,
    };
    assert_eq!(
        json["methodId"],
        serde_json::json!(format!(
            "0x{}",
            hex::encode(&borsh::to_vec(&body).unwrap()[..32])
        ))
    );
    assert_eq!(
        serde_json::from_value::<BatchProofMethodIdRpcResponse>(json.clone()).unwrap(),
        response
    );
    let mut without_prefix = serde_json::to_value(&response).unwrap();
    without_prefix["methodId"] =
        serde_json::json!("0100000002000000030000000400000005000000060000000700000008000000");
    assert_eq!(
        serde_json::from_value::<BatchProofMethodIdRpcResponse>(without_prefix).unwrap(),
        response
    );
    let mut malformed = serde_json::to_value(&response).unwrap();
    malformed["methodId"] = serde_json::json!("0x01");
    assert!(serde_json::from_value::<BatchProofMethodIdRpcResponse>(malformed).is_err());

    use sov_rollup_interface::rpc::{LatestDaStateRpcResponse, LightClientProofOutputRpcResponse};
    let output = LightClientProofOutputRpcResponse {
        l2_state_root: [0; 32],
        lcp_state_root: [0; 32],
        light_client_proof_method_id: PROGRAM,
        latest_da_state: LatestDaStateRpcResponse {
            block_hash: [0; 32],
            block_height: Default::default(),
            total_work: [0; 32],
            current_target_bits: Default::default(),
            epoch_start_time: Default::default(),
            prev_11_timestamps: [Default::default(); 11],
        },
        last_l2_height: Default::default(),
        last_sequencer_commitment_index: Default::default(),
    };
    let output_json = serde_json::to_value(&output).unwrap();
    assert_eq!(output_json["lightClientProofMethodId"], json["methodId"]);
    assert_eq!(
        serde_json::from_value::<LightClientProofOutputRpcResponse>(output_json)
            .unwrap()
            .light_client_proof_method_id,
        PROGRAM
    );
}

#[cfg(feature = "native")]
#[test]
fn compressed_verification_binds_the_native_digest_directly() {
    use sov_rollup_interface::zk::compressed::CompressedProof;

    let proof = CompressedProof {
        native_vkey: PROGRAM,
        proof: vec![],
        vkey: vec![],
    };
    // Matching native words reach the host's guest-only verification guard.
    assert_eq!(
        proof.verify(&PROGRAM, &[]).unwrap_err(),
        "Compressed SP1 proofs can only be verified in a guest"
    );
    let mut other = PROGRAM;
    other[7] += 1;
    assert_eq!(
        proof.verify(&other, &[]).unwrap_err(),
        "Compressed SP1 program mismatch"
    );
    // The guest must never take the proof from untrusted input instead of the proof stream.
    let with_payload = CompressedProof {
        proof: vec![1],
        ..proof.clone()
    };
    assert_eq!(
        with_payload.verify(&PROGRAM, &[]).unwrap_err(),
        "Compressed proof payload must use the native proof stream"
    );
    let noncanonical = CompressedProof {
        native_vkey: [KOALABEAR_P; 8],
        ..proof
    };
    assert!(noncanonical.verify(&noncanonical.native_vkey, &[]).is_err());
}
