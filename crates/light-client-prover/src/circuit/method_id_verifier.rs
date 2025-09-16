use alloy_primitives::eip191_hash_message;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
use k256::EncodedPoint;

// TODO: Implement error type
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

        // Ensure the signature is in the correct format (65 bytes: r(32) + s(32) + v(1))
        if signature_bytes.len() != 65 {
            continue;
        }

        // Calculate prehash of the message
        let prehash = eip191_hash_message(signature_message);

        let mut eip_191_signature = [0u8; 64];
        eip_191_signature[..64].copy_from_slice(&signature_bytes[..64]);

        let signature = k256::ecdsa::Signature::from_slice(eip_191_signature.as_slice()).unwrap();

        // Try verifying the signature
        if verifying_key
            .verify_prehash(prehash.as_slice(), &signature)
            .is_ok()
        {
            valid_signatures += 1;
        }
    }

    if valid_signatures >= 3 {
        true
    } else {
        false
    }
}

mod test_eip191 {
    use alloy_primitives::eip191_hash_message;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
    use k256::EncodedPoint;

    #[test]
    fn test_eip_191_sig() {
        // signature created with cast: cast wallet sign --private-key d38ba32d6971702225da49b49baac41c5a7ec2f5e3f2bb426976195ccd3266f7 0x48656c6c6f2c20776f726c6421
        let msg = b"Hello, world!";

        // Assert that the message hex is correct
        assert_eq!(hex::encode(msg.to_vec()), "48656c6c6f2c20776f726c6421");

        // Some randomly generated secret key
        let secret_key = "d38ba32d6971702225da49b49baac41c5a7ec2f5e3f2bb426976195ccd3266f7";
        let secret_key_bytes: [u8; 32] = hex::decode(secret_key).unwrap().try_into().unwrap();

        // Create signing key
        let signing_key = SigningKey::from_bytes(&secret_key_bytes.into()).unwrap();

        // Derive verifying key (public key)
        let verify_key = signing_key.verifying_key();

        // Get SEC1-encoded public key (uncompressed = 65 bytes)
        let pubkey_uncompressed: EncodedPoint = verify_key.to_encoded_point(false);
        let pubkey = VerifyingKey::from_encoded_point(&pubkey_uncompressed).unwrap();

        // Sign the message with eip-191 prefix
        let (mut eip_191_signature, prehash) = eip191_sign(msg, &secret_key_bytes);

        // cast wallet sign --private-key d38ba32d6971702225da49b49baac41c5a7ec2f5e3f2bb426976195ccd3266f7 0x48656c6c6f2c20776f726c6421
        // Output:
        // 0x52782f3d8fddd7e1bfaa718e4ca6f8c3581624880bae828c9e220628dcdbf55e40eedc5c0ee292cfe296492533bcdcec74836f8a4866e4f8b8308167853731731c

        // Assert that cast signature matches our signature
        assert_eq!(hex::encode(&eip_191_signature), "52782f3d8fddd7e1bfaa718e4ca6f8c3581624880bae828c9e220628dcdbf55e40eedc5c0ee292cfe296492533bcdcec74836f8a4866e4f8b8308167853731731c");

        let recovered_pub_key =
            recover_pub_key_from_cast_sig_and_hash(&eip_191_signature, prehash.as_slice());

        // Assert that the recovered public key matches the original public key
        assert_eq!(pubkey, recovered_pub_key);

        // drop last byte
        eip_191_signature.pop();

        let signature = k256::ecdsa::Signature::from_slice(eip_191_signature.as_slice()).unwrap();

        // Verify the signature using the prehash
        assert!(recovered_pub_key
            .verify_prehash(prehash.as_slice(), &signature)
            .is_ok());
        assert!(pubkey
            .verify_prehash(prehash.as_slice(), &signature)
            .is_ok());
    }

    fn recover_pub_key_from_cast_sig_and_hash(cast_sig: &[u8], hash: &[u8]) -> VerifyingKey {
        assert_eq!(cast_sig.len(), 65, "Invalid signature length");
        assert_eq!(hash.len(), 32, "Invalid hash length");

        let y_odd = cast_sig[64] - 27;
        let y_odd = y_odd != 0;

        let signature = k256::ecdsa::Signature::from_slice(&cast_sig[0..64]).unwrap();

        VerifyingKey::recover_from_prehash(&hash, &signature, RecoveryId::new(y_odd, false))
            .expect("Failed to recover public key")
    }

    /// Sign a message with EIP-191 prefixing and return (sig65, hash32)
    /// - sig65: r(32) || s(32) || v(1) with v in {27, 28}
    /// - hash32: keccak256(prefix || len || msg)
    pub fn eip191_sign(msg: &[u8], secret_key_bytes: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        // Build the signing key

        let signing_key =
            SigningKey::from_bytes(secret_key_bytes.into()).expect("invalid secp256k1 secret key");

        // EIP-191 prefixing, then keccak256
        let prehash = eip191_hash_message(msg);

        // Sign the prehash and get a RECOVERABLE signature (so we can emit v)
        let (rec_sig, recovery_id) = signing_key
            .sign_prehash_recoverable(&prehash.as_slice())
            .unwrap();

        // Serialize r||s (64 bytes)
        let rs = rec_sig.to_bytes(); // <[u8; 64]>
        let (r, s) = rs.split_at(32);

        // Compute v = 27 + recid (Ethereum style)
        let v_eth: u8 = 27 + (u8::from(recovery_id) & 1);

        // Assemble 65-byte Ethereum signature r||s||v
        let mut sig65 = Vec::with_capacity(65);
        sig65.extend_from_slice(r);
        sig65.extend_from_slice(s);
        sig65.push(v_eth);

        let mut hash32 = [0u8; 32];
        hash32.copy_from_slice(&prehash.as_slice());

        (sig65, hash32)
    }
}
