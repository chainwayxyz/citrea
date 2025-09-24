use alloy_primitives::eip191_hash_message;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

/// The three out of 5 signatures should be verified for the method id upgrade to be valid.
/// The signatures should be in the same order as the one in the initial values constants.
/// For each signature, the corresponding public key from the initial values constants is used to verify the signature.
/// If there are less than 3 valid signatures, the verification fails.
pub fn verify_method_id_security_council(
    initial_da_pubkeys: [[u8; 33]; 5],
    msg: &[u8],
    signatures_with_idx: &[([u8; 64], u8); 3],
) -> bool {
    // EIP-191 prefix + keccak256 → 32-byte prehash
    let prehash = eip191_hash_message(msg);

    // Check that signature indices are within bounds
    for &(_, index) in signatures_with_idx {
        if index >= 5 {
            log!("Invalid signature index: {}", index);
            return false;
        }
    }

    // Check for duplicate indices
    if signatures_with_idx[0].1 == signatures_with_idx[1].1
        || signatures_with_idx[0].1 == signatures_with_idx[2].1
        || signatures_with_idx[1].1 == signatures_with_idx[2].1
    {
        log!("Duplicate signature indexes found");
        return false;
    }

    for signature_with_idx in signatures_with_idx.iter() {
        let signature = signature_with_idx.0;
        let pubkey_idx = signature_with_idx.1;
        let const_pubkey = initial_da_pubkeys[pubkey_idx as usize];

        // ensure the inscription pubkey matches the expected constant (compressed 33B)
        let verifying_key = VerifyingKey::from_sec1_bytes(const_pubkey.as_slice())
            .expect("Initial DA pubkeys must be parsable to k256 VerifyingKey form sec1 bytes");

        let Ok(parsed_sig) = Signature::from_bytes(&signature.into()) else {
            log!("Invalid signature format");
            return false; // invalid signature format, fail
        };

        // verify prehash with the matching verifying key
        if verifying_key
            .verify_prehash(prehash.as_slice(), &parsed_sig)
            .is_err()
        {
            log!("Signature verification failed for index: {}", pubkey_idx);
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use sov_rollup_interface::da::{BatchProofMethodId, BatchProofMethodIdBody};

    use super::*;
    use crate::{create_valid_signatures, generate_initial_pub_keys_with_signers};

    #[test]
    fn test_valid_signatures() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
        };
        let msg = body.serialize();
        let prehash = eip191_hash_message(msg);

        let (initial_pubkeys, signers) = generate_initial_pub_keys_with_signers();

        let signatures_with_index = create_valid_signatures(&signers, &prehash);

        let batch_proof_method_id = BatchProofMethodId {
            body: BatchProofMethodIdBody {
                method_id: [0u32; 8],
                activation_l2_height: 0,
            },
            signatures_with_index,
        };

        assert!(verify_method_id_security_council(
            initial_pubkeys,
            batch_proof_method_id.body.serialize().as_slice(),
            &batch_proof_method_id.signatures_with_index
        ));
    }

    #[test]
    fn test_invalid_signatures() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
        };
        let msg = body.serialize();
        let prehash = eip191_hash_message(msg);

        let (initial_pubkeys, signers) = generate_initial_pub_keys_with_signers();

        let mut signatures_with_index = create_valid_signatures(&signers, &prehash);

        // Invalidate one signature by changing one byte
        signatures_with_index[0].0[0] ^= 0xFF;

        let batch_proof_method_id = BatchProofMethodId {
            body,
            signatures_with_index,
        };
        assert!(!verify_method_id_security_council(
            initial_pubkeys,
            batch_proof_method_id.body.serialize().as_slice(),
            &batch_proof_method_id.signatures_with_index
        ));
    }

    #[test]
    fn test_duplicate_index() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
        };
        let msg = body.serialize();
        let prehash = eip191_hash_message(msg);

        let (initial_pubkeys, signers) = generate_initial_pub_keys_with_signers();

        let mut signatures_with_index = create_valid_signatures(&signers, &prehash);

        // Duplicate the first signature's index
        signatures_with_index[1].1 = signatures_with_index[0].1;

        let batch_proof_method_id = BatchProofMethodId {
            body,
            signatures_with_index,
        };
        assert!(!verify_method_id_security_council(
            initial_pubkeys,
            batch_proof_method_id.body.serialize().as_slice(),
            &batch_proof_method_id.signatures_with_index
        ));
    }

    #[test]
    fn test_out_of_bounds_index() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
        };
        let msg = body.serialize();
        let prehash = eip191_hash_message(msg);
        let (initial_pubkeys, signers) = generate_initial_pub_keys_with_signers();
        let mut signatures_with_index = create_valid_signatures(&signers, &prehash);
        // Set an out-of-bounds index
        signatures_with_index[0].1 = 5; // valid indexes are 0-
        let batch_proof_method_id = BatchProofMethodId {
            body,
            signatures_with_index,
        };
        assert!(!verify_method_id_security_council(
            initial_pubkeys,
            batch_proof_method_id.body.serialize().as_slice(),
            &batch_proof_method_id.signatures_with_index
        ));
    }

    #[test]
    fn test_signature_index_swapped() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
        };
        let msg = body.serialize();
        let prehash = eip191_hash_message(msg);

        let (initial_pubkeys, signers) = generate_initial_pub_keys_with_signers();

        let mut signatures_with_index = create_valid_signatures(&signers, &prehash);

        // Swap pubkey indexes of two signatures
        let tmp = signatures_with_index[0].1;
        signatures_with_index[0].1 = signatures_with_index[1].1;
        signatures_with_index[1].1 = tmp;

        let batch_proof_method_id = BatchProofMethodId {
            body,
            signatures_with_index,
        };

        // Should not verify because points to different pubkeys now
        assert!(!verify_method_id_security_council(
            initial_pubkeys,
            batch_proof_method_id.body.serialize().as_slice(),
            &batch_proof_method_id.signatures_with_index
        ));
    }
}

#[test]
// Compares signature created with cast and our implementation
fn test_eip191_signature_verification() {
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    // signature created with cast: cast wallet sign --private-key d38ba32d6971702225da49b49baac41c5a7ec2f5e3f2bb426976195ccd3266f7 0x48656c6c6f2c20776f726c6421
    let msg = b"Hello, world!";

    // Assert that the message hex is correct
    assert_eq!(hex::encode(msg), "48656c6c6f2c20776f726c6421");

    // Some randomly generated secret key
    let secret_key = "d38ba32d6971702225da49b49baac41c5a7ec2f5e3f2bb426976195ccd3266f7";
    let secret_key_bytes: [u8; 32] = hex::decode(secret_key).unwrap().try_into().unwrap();
    let signer = PrivateKeySigner::from_bytes(&secret_key_bytes.into()).unwrap();
    let verifying_key = signer.credential().verifying_key();
    let pubkey = verifying_key.to_sec1_bytes();

    // Keccak256 is used inside
    let prehash = eip191_hash_message(msg);

    let eip_191_signature = signer.sign_hash_sync(&prehash).unwrap();
    let recovered_pub_key =
        recover_pub_key_from_cast_sig_and_hash(&eip_191_signature.as_bytes(), prehash.as_slice());

    assert_eq!(pubkey, recovered_pub_key.to_sec1_bytes());

    // cast wallet sign --private-key d38ba32d6971702225da49b49baac41c5a7ec2f5e3f2bb426976195ccd3266f7 0x48656c6c6f2c20776f726c6421
    // Output:
    // 0x52782f3d8fddd7e1bfaa718e4ca6f8c3581624880bae828c9e220628dcdbf55e40eedc5c0ee292cfe296492533bcdcec74836f8a4866e4f8b8308167853731731c
    let sig_bytes = eip_191_signature.as_bytes();
    // Assert that cast signature matches our signature
    assert_eq!(hex::encode(sig_bytes), "52782f3d8fddd7e1bfaa718e4ca6f8c3581624880bae828c9e220628dcdbf55e40eedc5c0ee292cfe296492533bcdcec74836f8a4866e4f8b8308167853731731c");

    let signature =
        k256::ecdsa::Signature::from_slice(&eip_191_signature.as_bytes()[0..64]).unwrap();

    assert!(verifying_key
        .verify_prehash(prehash.as_slice(), &signature)
        .is_ok());
}

/// Recovers the public key from a cast-style signature (65 bytes: r(32) + s(32) + v(1)) and the message hash.
#[cfg(test)]
fn recover_pub_key_from_cast_sig_and_hash(cast_sig: &[u8], hash: &[u8]) -> VerifyingKey {
    use k256::ecdsa::RecoveryId;
    assert_eq!(cast_sig.len(), 65, "Invalid signature length");
    assert_eq!(hash.len(), 32, "Invalid hash length");

    let y_odd = cast_sig[64] - 27;
    let y_odd = y_odd != 0;

    let signature = k256::ecdsa::Signature::from_slice(&cast_sig[0..64]).unwrap();

    VerifyingKey::recover_from_prehash(hash, &signature, RecoveryId::new(y_odd, false))
        .expect("Failed to recover public key")
}
