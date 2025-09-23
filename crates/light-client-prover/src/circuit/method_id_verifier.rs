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
    signatures: &[Signature; 5],
) -> bool {
    // EIP-191 prefix + keccak256 → 32-byte prehash
    let prehash = eip191_hash_message(msg);

    let mut valid = 0usize;

    for (const_pubkey33, sig) in initial_da_pubkeys.iter().zip(signatures.iter()) {
        // ensure the inscription pubkey matches the expected constant (compressed 33B)
        let verifying_key = VerifyingKey::from_sec1_bytes(const_pubkey33)
            .expect("Initial DA pubkeys must be parsable to k256 VerifyingKey form sec1 bytes");

        // verify prehash with the matching verifying key
        if verifying_key
            .verify_prehash(prehash.as_slice(), sig)
            .is_ok()
        {
            valid += 1;
            if valid >= 3 {
                return true; // short-circuit: 3-of-5 satisfied
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use sov_rollup_interface::da::{BatchProofMethodId, BatchProofMethodIdBody};

    use super::*;

    fn from_vec_to_sigs(vec: Vec<Vec<u8>>) -> [Signature; 5] {
        let mut sigs = Vec::new();
        for v in vec.into_iter() {
            sigs.push(Signature::from_bytes((&v[..]).into()).unwrap());
        }
        sigs.try_into().unwrap()
    }

    #[test]
    fn test_valid_signatures() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
        };
        let msg = body.serialize();
        let prehash = eip191_hash_message(msg);
        let mut initial_da_pubkeys = [[0u8; 33]; 5];
        let mut pubkeys_in_inscription = Vec::new();
        let mut signatures_in_inscription = Vec::new();

        // Generate 5 valid keypairs and signatures
        for (i, initial_pubkey) in initial_da_pubkeys.iter_mut().enumerate() {
            let secret_key = [i as u8 + 1; 32];
            let signer = PrivateKeySigner::from_bytes(&secret_key.into()).unwrap();
            let verifying_key = signer.credential().verifying_key();
            let pubkey = verifying_key.to_sec1_bytes();
            *initial_pubkey = pubkey.to_vec().try_into().unwrap();
            pubkeys_in_inscription.push(pubkey.to_vec());

            let sig = signer.sign_hash_sync(&prehash).unwrap();
            let signature = sig.as_bytes()[0..64].to_vec();

            signatures_in_inscription.push(signature);
        }

        let batch_proof_method_id = BatchProofMethodId {
            body: BatchProofMethodIdBody {
                method_id: [0u32; 8],
                activation_l2_height: 0,
            },
            signatures: from_vec_to_sigs(signatures_in_inscription.clone()),
        };

        assert!(verify_method_id_security_council(
            initial_da_pubkeys,
            batch_proof_method_id.body.serialize().as_slice(),
            &batch_proof_method_id.signatures
        ));
    }

    #[test]
    fn test_less_than_three_valid_signatures() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
        };
        let msg = body.serialize();
        let prehash = eip191_hash_message(msg);
        let mut initial_da_pubkeys = [[0u8; 33]; 5];
        let mut pubkeys_in_inscription = Vec::new();
        let mut signatures_in_inscription = Vec::new();

        // Generate 5 valid keypairs and signatures
        for (i, initial_pubkey) in initial_da_pubkeys.iter_mut().enumerate() {
            let secret_key = [i as u8 + 1; 32];
            let signer = PrivateKeySigner::from_bytes(&secret_key.into()).unwrap();
            let verifying_key = signer.credential().verifying_key();
            let pubkey = verifying_key.to_sec1_bytes();
            *initial_pubkey = pubkey.to_vec().try_into().unwrap();
            pubkeys_in_inscription.push(pubkey.to_vec());

            let sig = signer.sign_hash_sync(&prehash).unwrap();
            let signature = sig.as_bytes()[0..64].to_vec();
            signatures_in_inscription.push(signature);
        }

        // Corrupt 3 signatures
        signatures_in_inscription[0][0] ^= 0xFF;
        signatures_in_inscription[1][0] ^= 0xFF;
        signatures_in_inscription[2][0] ^= 0xFF;

        let batch_proof_method_id = BatchProofMethodId {
            body,
            signatures: from_vec_to_sigs(signatures_in_inscription.clone()),
        };
        assert!(!verify_method_id_security_council(
            initial_da_pubkeys,
            batch_proof_method_id.body.serialize().as_slice(),
            &batch_proof_method_id.signatures
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
