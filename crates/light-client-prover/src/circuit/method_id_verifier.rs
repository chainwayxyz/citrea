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
        if verifying_key.verify_prehash(prehash, signature).is_ok() {
            valid_signatures += 1;
        }
    }

    if valid_signatures >= 3 {
        true
    } else {
        false
    }
}
