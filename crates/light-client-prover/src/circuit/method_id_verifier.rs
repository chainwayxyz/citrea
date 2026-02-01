use alloy_primitives::{eip191_hash_message, keccak256, Address, B256};
use alloy_sol_types::{eip712_domain, SolStruct};
use k256::ecdsa::VerifyingKey;
use sov_rollup_interface::da::{
    BatchProofMethodIdBody, SECURITY_COUNCIL_SIGNATURE_SIZE, SECURITY_COUNCIL_SIGNATURE_THRESHOLD,
};

use crate::circuit::{BatchProofMethodIdUpdate, SECURITY_COUNCIL_MEMBER_COUNT};

/// Error type for public key recovery operations
#[derive(Debug, Clone)]
pub enum PubKeyRecoveryError {
    /// Invalid signature length
    InvalidSignatureLength,
    /// Invalid hash length
    InvalidHashLength,
    /// Invalid recovery ID (v value)
    InvalidRecoveryId(u8),
    /// Failed to parse signature bytes
    InvalidSignatureBytes(String),
    /// Failed to recover the public key
    RecoveryFailed(String),
}

impl std::fmt::Display for PubKeyRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubKeyRecoveryError::InvalidSignatureLength => write!(f, "Invalid Signature Length"),
            PubKeyRecoveryError::InvalidHashLength => write!(f, "Invalid Hash Length"),
            PubKeyRecoveryError::InvalidRecoveryId(recovery_id) => {
                write!(f, "Invalid Recovery Id: {recovery_id}")
            }
            PubKeyRecoveryError::InvalidSignatureBytes(bytes_str) => {
                write!(f, "Invalid Signature Bytes: {bytes_str}")
            }
            PubKeyRecoveryError::RecoveryFailed(e) => write!(f, "Recovery Failed with error: {e}"),
        }
    }
}

/// The three out of 5 signatures should be verified for the method id upgrade to be valid.
/// For each signature, the corresponding public key from the initial values constants is used to verify the signature.
/// If there are less than 3 valid signatures, the verification fails.
/// Note that the pubkey indices of signatures must be in strict ascending order and within bounds [0,(SECURITY_COUNCIL_MEMBER_COUNT - 1)]
pub fn verify_method_id_security_council(
    initial_da_addresses: [Address; SECURITY_COUNCIL_MEMBER_COUNT],
    batch_proof_method_id_body: BatchProofMethodIdBody,
    signatures_with_idx: &[([u8; SECURITY_COUNCIL_SIGNATURE_SIZE], u8);
         SECURITY_COUNCIL_SIGNATURE_THRESHOLD],
    domain_name: String,
    chain_id: u64,
) -> bool {
    let domain = eip712_domain! {
        name: domain_name,
        version: "1",
        chain_id: chain_id,
    };

    let batch_proof_method_id_update = BatchProofMethodIdUpdate::from(batch_proof_method_id_body);

    // this is basically keccak256("\x19\x01" ‖ domainSeparator ‖ hashStruct(message))
    let prehash = batch_proof_method_id_update.eip712_signing_hash(&domain);

    // Check that signature indices are within bounds
    for &(_, index) in signatures_with_idx {
        if index >= 5 {
            log!("Invalid signature index: {}", index);
            return false;
        }
    }

    // Make sure the indexes are in ascending order to prevent duplicates
    for i in 0..signatures_with_idx.len() - 1 {
        if signatures_with_idx[i].1 >= signatures_with_idx[i + 1].1 {
            log!(
                "Signature indices are not in ascending order, failing indices: {}, {}",
                signatures_with_idx[i].1,
                signatures_with_idx[i + 1].1
            );
            return false;
        }
    }

    for signature_with_idx in signatures_with_idx.iter() {
        let signature = signature_with_idx.0;
        let address_idx = signature_with_idx.1;
        let const_address = initial_da_addresses[address_idx as usize];

        let recovered_pubkey = match recover_pub_key_from_signature_and_prehash(
            signature.as_slice(),
            prehash.as_slice(),
        ) {
            Ok(recovered_pubkey) => recovered_pubkey,
            Err(e) => {
                log!(
                    "Failed to recover public key from signature for index {}: {:?}",
                    address_idx,
                    e.to_string()
                );
                return false;
            }
        };

        let ep = recovered_pubkey.to_encoded_point(false); // uncompressed form

        let bytes = ep.as_bytes();
        debug_assert_eq!(bytes[0], 0x04);

        // Hash the 64 bytes X||Y (skip the 0x04 prefix)
        let hash = keccak256(&bytes[1..]);

        // Take last 20 bytes
        let address = Address::from_slice(&hash[12..]);

        if address != const_address {
            log!(
                "Recovered address does not match constant address for index: {}",
                address_idx
            );
            return false;
        }
    }

    true
}

/// Recovers the public key from a signature (65 bytes: r(32) + s(32) + v(1)) and the message prehash.
fn recover_pub_key_from_signature_and_prehash(
    signature: &[u8],
    message_prehash: &[u8],
) -> Result<VerifyingKey, PubKeyRecoveryError> {
    use k256::ecdsa::RecoveryId;

    if signature.len() != 65 {
        return Err(PubKeyRecoveryError::InvalidSignatureLength);
    }
    if message_prehash.len() != 32 {
        return Err(PubKeyRecoveryError::InvalidHashLength);
    }

    let v = signature[64];
    let recid_u8 = match v {
        0..=3 => v,
        27..=30 => v - 27,
        _ => return Err(PubKeyRecoveryError::InvalidRecoveryId(v)),
    };

    let mut y_odd = (recid_u8 & 1) == 1;
    let x_reduced = (recid_u8 & 2) == 2;

    let mut signature = k256::ecdsa::Signature::from_slice(&signature[0..64])
        .map_err(|e| PubKeyRecoveryError::InvalidSignatureBytes(format!("{e:?}")))?;

    // low-s normalization requires flipping parity
    if let Some(s) = signature.normalize_s() {
        signature = s;
        y_odd = !y_odd;
    }

    VerifyingKey::recover_from_prehash(
        message_prehash,
        &signature,
        RecoveryId::new(y_odd, x_reduced),
    )
    .map_err(|e| PubKeyRecoveryError::RecoveryFailed(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use sov_rollup_interface::da::{BatchProofMethodId, BatchProofMethodIdBody};
    use sov_rollup_interface::Network;

    use super::*;
    use crate::circuit::citrea_network_to_chain_id;
    use crate::circuit::initial_values::bitcoinda;
    use crate::{create_valid_signatures, generate_initial_addresses_with_signers};

    #[test]
    fn test_valid_signatures() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };

        let payload = BatchProofMethodIdUpdate::from(body);

        let (initial_addresses, signers) = generate_initial_addresses_with_signers();

        let signatures_with_index = create_valid_signatures(&signers, &payload);

        let batch_proof_method_id = BatchProofMethodId {
            body: BatchProofMethodIdBody {
                method_id: [0u32; 8],
                activation_l2_height: 0,
                chain_id: citrea_network_to_chain_id(Network::Nightly),
            },
            signatures_with_index,
        };

        assert!(verify_method_id_security_council(
            initial_addresses,
            batch_proof_method_id.body,
            &batch_proof_method_id.signatures_with_index,
            bitcoinda::NIGHTLY_EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            citrea_network_to_chain_id(Network::Nightly),
        ));
    }

    #[test]
    fn test_invalid_signatures() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };
        let payload = BatchProofMethodIdUpdate::from(body.clone());

        let (initial_addresses, signers) = generate_initial_addresses_with_signers();

        let mut signatures_with_index = create_valid_signatures(&signers, &payload);

        // Invalidate one signature by changing one byte
        signatures_with_index[0].0[0] ^= 0xFF;

        let batch_proof_method_id = BatchProofMethodId {
            body,
            signatures_with_index,
        };
        assert!(!verify_method_id_security_council(
            initial_addresses,
            batch_proof_method_id.body,
            &batch_proof_method_id.signatures_with_index,
            bitcoinda::NIGHTLY_EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            citrea_network_to_chain_id(Network::Nightly),
        ));
    }

    #[test]
    fn test_duplicate_index() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };
        let payload = BatchProofMethodIdUpdate::from(body.clone());

        let (initial_addresses, signers) = generate_initial_addresses_with_signers();

        let mut signatures_with_index = create_valid_signatures(&signers, &payload);

        // Duplicate the first signature's index
        signatures_with_index[1].1 = signatures_with_index[0].1;

        let batch_proof_method_id = BatchProofMethodId {
            body,
            signatures_with_index,
        };
        assert!(!verify_method_id_security_council(
            initial_addresses,
            batch_proof_method_id.body,
            &batch_proof_method_id.signatures_with_index,
            bitcoinda::NIGHTLY_EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            citrea_network_to_chain_id(Network::Nightly),
        ));
    }

    #[test]
    fn test_out_of_bounds_index() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };
        let payload = BatchProofMethodIdUpdate::from(body.clone());
        let (initial_addresses, signers) = generate_initial_addresses_with_signers();
        let mut signatures_with_index = create_valid_signatures(&signers, &payload);
        // Set an out-of-bounds index
        signatures_with_index[0].1 = 5; // valid indexes are 0-
        let batch_proof_method_id = BatchProofMethodId {
            body,
            signatures_with_index,
        };
        assert!(!verify_method_id_security_council(
            initial_addresses,
            batch_proof_method_id.body,
            &batch_proof_method_id.signatures_with_index,
            bitcoinda::NIGHTLY_EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            citrea_network_to_chain_id(Network::Nightly),
        ));
    }

    #[test]
    fn test_signature_index_swapped() {
        let body = BatchProofMethodIdBody {
            method_id: [0u32; 8],
            activation_l2_height: 0,
            chain_id: citrea_network_to_chain_id(Network::Nightly),
        };
        let payload = BatchProofMethodIdUpdate::from(body.clone());

        let (initial_addresses, signers) = generate_initial_addresses_with_signers();

        let mut signatures_with_index = create_valid_signatures(&signers, &payload);

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
            initial_addresses,
            batch_proof_method_id.body,
            &batch_proof_method_id.signatures_with_index,
            bitcoinda::NIGHTLY_EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            citrea_network_to_chain_id(Network::Nightly),
        ));
    }
}

#[test]
// Compares signature created with cast and our implementation
fn test_eip191_signature_verification() {
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

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
    let recovered_pub_key = recover_pub_key_from_signature_and_prehash(
        &eip_191_signature.as_bytes(),
        prehash.as_slice(),
    )
    .unwrap();

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
