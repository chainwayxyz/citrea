use alloy_primitives::eip191_hash_message;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::VerifyingKey;
use k256::EncodedPoint;

/// The three out of 5 signatures should be verified for the method id upgrade to be valid.
/// The signatures and pub keys should be in the same order as the one in the initial values constants.
pub(crate) fn verify_method_id_security_council(
    initial_da_pubkeys: [[u8; 33]; 5],
    pubkeys_in_inscription: Vec<Vec<u8>>,
    signatures_in_inscription: Vec<Vec<u8>>,
    signature_message: &[u8],
) -> bool {
    // There should be exactly 5 pubkeys and signatures in the inscription
    if pubkeys_in_inscription.len() != 5 || signatures_in_inscription.len() != 5 {
        return false;
    }

    // The number of pubkeys in the inscription should match the number of initial DA pubkeys
    if initial_da_pubkeys.len() != pubkeys_in_inscription.len() {
        return false;
    }

    let mut valid_signatures = 0;

    for (pubkey_idx, (const_pub_key, inscription_pub_key)) in initial_da_pubkeys
        .iter()
        .zip(pubkeys_in_inscription.iter())
        .enumerate()
    {
        // The pubkeys should match
        if const_pub_key != inscription_pub_key.as_slice() {
            continue;
        }

        let signature_bytes = &signatures_in_inscription[pubkey_idx];

        // Decode the public key
        let encoded_point = match EncodedPoint::from_bytes(inscription_pub_key.as_slice()) {
            Ok(point) => point,
            Err(e) => {
                log!("Failed to decode public key: {:?}", e);
                continue;
            }
        };

        let verifying_key = match VerifyingKey::from_encoded_point(&encoded_point) {
            Ok(key) => key,
            Err(e) => {
                log!("Failed to decode verifying key: {:?}", e);
                continue;
            }
        };

        // Ensure the signature is in the correct format (64 bytes: r(32) + s(32))
        if signature_bytes.len() != 64 {
            continue;
        }

        // Calculate prehash of the message
        let prehash = eip191_hash_message(signature_message);

        let Ok(signature) = k256::ecdsa::Signature::from_slice(signature_bytes.as_slice()) else {
            log!("Failed to parse signature");
            continue;
        };

        // Try verifying the signature
        if verifying_key
            .verify_prehash(prehash.as_slice(), &signature)
            .is_ok()
        {
            valid_signatures += 1;
        }
    }

    valid_signatures >= 3
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

/// Signs a message with the given secret key using EIP-191.
#[cfg(test)]
pub(crate) fn eip191_sign(msg: &[u8], secret_key: &[u8; 32]) -> (k256::ecdsa::Signature, [u8; 32]) {
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    let signer = PrivateKeySigner::from_bytes(&secret_key.into()).unwrap();

    let prehash = eip191_hash_message(msg);

    let sig = signer.sign_hash_sync(&prehash).unwrap();
    let signature = k256::ecdsa::Signature::from_slice(&sig.as_bytes()[0..64]).unwrap();

    (signature, *prehash)
}
