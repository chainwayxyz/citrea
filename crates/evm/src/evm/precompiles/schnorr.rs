use revm_precompile::{u64_to_address, Bytes, Precompile, PrecompileError, PrecompileOutput, PrecompileResult, PrecompileWithAddress};
use secp256k1::SECP256K1;
use secp256k1::{schnorr::Signature, Message, XOnlyPublicKey};

const SCHNORRVERIFY_BASE: u64 = 3500;
/// Precompile for verifying Schnorr signatures.
pub const SCHNORRVERIFY: PrecompileWithAddress = PrecompileWithAddress(u64_to_address(0x200), Precompile::Standard(schnorr_verify));

/// Verifies a Schnorr signature.
pub fn schnorr_verify(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if SCHNORRVERIFY_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }
    // Parse input, first 32 bytes are the public key, next 32 bytes is the message hash and the last 64 bytes are the signature
    let public_key = XOnlyPublicKey::from_slice(&input[..32]);
    let message = Message::from_digest_slice(&input[32..64]);
    let signature = Signature::from_slice(&input[64..]);

    let result;
    if public_key.is_err() || message.is_err() || signature.is_err() {
        result = false;
    }
    else {
        let public_key = public_key.unwrap();
        let message = message.unwrap();
        let signature = signature.unwrap();
        result = SECP256K1.verify_schnorr(&signature, &message, &public_key).is_ok();
    }
    
    Ok(PrecompileOutput::new(SCHNORRVERIFY_BASE, Bytes::from([result as u8])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Keypair;

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