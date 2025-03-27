use revm_precompile::{u64_to_address, Bytes, Precompile, PrecompileError, PrecompileOutput, PrecompileResult, PrecompileWithAddress};
use k256::schnorr::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

const SCHNORRVERIFY_BASE: u64 = 3500;
/// Precompile for verifying Schnorr signatures.
pub const SCHNORRVERIFY: PrecompileWithAddress = PrecompileWithAddress(u64_to_address(0x200), Precompile::Standard(schnorr_verify));

/// Verifies a Schnorr signature.
pub fn schnorr_verify(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if SCHNORRVERIFY_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }
    let result = verify_sig(input);
    Ok(PrecompileOutput::new(SCHNORRVERIFY_BASE, Bytes::from([result as u8])))
}

fn verify_sig(input: &Bytes) -> bool {
    if input.len() != 128 {
        return false;
    }
    let Ok(verifying_key) = VerifyingKey::from_bytes(&input[..32]) else { return false; };
    let message = &input[32..64];
    let Ok(signature) = Signature::try_from(&input[64..]) else { return false; };

    verifying_key.verify_prehash(&message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Message, XOnlyPublicKey, SECP256K1};

    #[test]
    fn test_invalid_signature() {
        assert_eq!(super::schnorr_verify(&Bytes::from([0; 128]), SCHNORRVERIFY_BASE), Ok(PrecompileOutput::new(SCHNORRVERIFY_BASE, Bytes::from([0]))));
    }

    #[test]
    fn test_valid_signature() {
        let keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let message = Message::from_digest_slice(&[1; 32]).unwrap();
        let signature = SECP256K1.sign_schnorr_no_aux_rand(&message, &keypair);
        let public_key = XOnlyPublicKey::from_keypair(&keypair).0;
        let mut input = Vec::new();
        input.extend_from_slice(&public_key.serialize());
        input.extend_from_slice(message.as_ref());
        input.extend_from_slice(signature.as_ref());
        assert_eq!(super::schnorr_verify(&Bytes::from(input), SCHNORRVERIFY_BASE), Ok(PrecompileOutput::new(SCHNORRVERIFY_BASE, Bytes::from([1]))));
    }
}