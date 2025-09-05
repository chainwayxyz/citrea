use alloy_primitives::{Bytes, B256};
use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};
use revm_precompile::{
    u64_to_address, PrecompileError, PrecompileOutput, PrecompileResult, PrecompileWithAddress,
};

// Benchmarks show that the zk cycle counts for schorr verification is
// %33 more than p256r1 verification. So we set the base gas cost
// to be 4600 as 4600 ~ 1.33 * 3450 (p256r1 base gas cost).
const SCHNORRVERIFY_BASE: u64 = 4600;
/// Precompile for verifying Schnorr signatures.
pub const SCHNORRVERIFY: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(0x200), schnorr_verify);

/// Schnorr signature verification over secp256k1 curve as described in [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
///
/// The return value is empty bytes for unverified and 0x0000000000000000000000000000000000000000000000000000000000000001 for verified input case.
///
/// The input must be 128 bytes long and formatted as follows:
///
/// - 32 bytes: public key
/// - 32 bytes: message hash
/// - 64 bytes: signature
pub fn schnorr_verify(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if SCHNORRVERIFY_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = verify_sig(input).map_or_else(Bytes::new, |_| B256::with_last_byte(1).into());

    Ok(PrecompileOutput::new(SCHNORRVERIFY_BASE, result))
}

fn verify_sig(input: &Bytes) -> Option<()> {
    if input.len() != 128 {
        return None;
    }
    let verifying_key = VerifyingKey::from_bytes(&input[..32]).ok()?;
    let message = &input[32..64];
    let signature = Signature::try_from(&input[64..]).ok()?;
    verifying_key.verify_prehash(message, &signature).ok()
}

#[cfg(test)]
mod tests {
    use alloy::hex::FromHex;
    use rstest::rstest;
    use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};

    use super::*;

    const TRUE_32_BYTES: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    fn random_signature() -> (XOnlyPublicKey, [u8; 32], secp256k1::schnorr::Signature) {
        let keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let message = [1; 32];
        let signature = SECP256K1.sign_schnorr_no_aux_rand(&message, &keypair);
        let public_key = XOnlyPublicKey::from_keypair(&keypair).0;

        // sanitiy check
        signature.verify(&message, &public_key).unwrap();

        (public_key, message, signature)
    }

    #[test]
    fn test_invalid_signature() {
        assert_eq!(
            schnorr_verify(&Bytes::from([0; 128]), SCHNORRVERIFY_BASE),
            Ok(PrecompileOutput::new(SCHNORRVERIFY_BASE, Bytes::new()))
        );

        let (public_key, message, signature) = random_signature();

        let mut raw_sig = signature.to_byte_array();
        raw_sig[0] ^= 1;

        let mut input = Vec::with_capacity(128);
        input.extend_from_slice(&public_key.serialize());
        input.extend_from_slice(message.as_ref());
        input.extend_from_slice(&raw_sig);

        assert_eq!(
            schnorr_verify(&Bytes::from(input), SCHNORRVERIFY_BASE),
            Ok(PrecompileOutput::new(SCHNORRVERIFY_BASE, Bytes::new()))
        );

        let (public_key, _, _) = random_signature();

        let mut input = Vec::with_capacity(128);
        input.extend_from_slice(&public_key.serialize());
        input.extend_from_slice(message.as_ref());
        input.extend_from_slice(signature.as_ref());

        assert_eq!(
            schnorr_verify(&Bytes::from(input), SCHNORRVERIFY_BASE),
            Ok(PrecompileOutput::new(SCHNORRVERIFY_BASE, Bytes::new()))
        )
    }

    #[test]
    fn invalid_input_len() {
        assert_eq!(
            schnorr_verify(&Bytes::from([0; 127]), SCHNORRVERIFY_BASE),
            Ok(PrecompileOutput::new(SCHNORRVERIFY_BASE, Bytes::new()))
        );
        assert_eq!(
            schnorr_verify(&Bytes::from([0; 129]), SCHNORRVERIFY_BASE),
            Ok(PrecompileOutput::new(SCHNORRVERIFY_BASE, Bytes::new()))
        );
    }

    #[test]
    fn test_insufficient_gas() {
        let (public_key, message, signature) = random_signature();
        let mut input = Vec::with_capacity(128);
        input.extend_from_slice(&public_key.serialize());
        input.extend_from_slice(message.as_ref());
        input.extend_from_slice(signature.as_ref());

        assert_eq!(
            schnorr_verify(&Bytes::from(input), SCHNORRVERIFY_BASE - 1),
            Err(PrecompileError::OutOfGas)
        );
    }

    #[test]
    fn test_no_gas_over_charge() {
        let (public_key, message, signature) = random_signature();
        let mut input = Vec::with_capacity(128);
        input.extend_from_slice(&public_key.serialize());
        input.extend_from_slice(message.as_ref());
        input.extend_from_slice(signature.as_ref());

        let result = schnorr_verify(&Bytes::from(input), SCHNORRVERIFY_BASE * 2).unwrap();

        assert_eq!(result.gas_used, SCHNORRVERIFY_BASE);
    }

    #[test]
    fn test_valid_signature() {
        for _ in 0..1000 {
            let (public_key, message, signature) = random_signature();

            let mut input = Vec::with_capacity(128);
            input.extend_from_slice(&public_key.serialize());
            input.extend_from_slice(message.as_ref());
            input.extend_from_slice(signature.as_ref());

            assert_eq!(
                schnorr_verify(&Bytes::from(input), SCHNORRVERIFY_BASE),
                Ok(PrecompileOutput::new(
                    SCHNORRVERIFY_BASE,
                    Bytes::from(TRUE_32_BYTES)
                ))
            );
        }
    }

    // Test vectors from BIP340
    //
    // These tests are actually run in `k256` crate also, however, we'd like to see them pass here as well
    #[rstest]
    #[case::ok_1("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B94DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B969670300000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4", true)]
    #[case::fail_public_key_not_on_curve("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C896CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false)]
    #[case::fail_even_y_r_false("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", false)]
    #[case::fail_negated_message("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C891FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD", false)]
    #[case::fail_negated_s_value("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C896CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6", false)]
    #[case::fail_sg_ep_is_infinite_1("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C890000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051", false)]
    #[case::fail_sg_ep_is_infinite_2("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C8900000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197", false)]
    #[case::fail_sig_0_32_not_valid_x("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C894A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false)]
    #[case::fail_sig_0_32_equal_to_field_size("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false)]
    #[case::fail_sig_32_64_equal_to_field_size("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C896CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", false)]
    #[case::fail_pub_key_not_valid_x("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C896CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false)]
    fn test_test_vectors(#[case] input: &str, #[case] success: bool) {
        let input = Bytes::from_hex(input).unwrap();
        let result = schnorr_verify(&input, SCHNORRVERIFY_BASE).unwrap();
        assert_eq!(result.gas_used, SCHNORRVERIFY_BASE);
        if success {
            assert_eq!(result.bytes, Bytes::from(TRUE_32_BYTES));
        } else {
            assert_eq!(result.bytes, Bytes::new());
        }
    }
}

mod anan {
    use alloy_primitives::{keccak256, normalize_v, Keccak256};
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::signature::{DigestSigner, DigestVerifier, Verifier};
    use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
    use k256::elliptic_curve::SecretKey;
    use k256::{EncodedPoint, Secp256k1};
    use sha2::Digest;

    #[test]
    fn test_eip_191_sig() {
        let msg = b"Hello, world!";
        let secret_key = "d38ba32d6971702225da49b49baac41c5a7ec2f5e3f2bb426976195ccd3266f7";
        let secret_key_bytes: [u8; 32] = hex::decode(secret_key).unwrap().try_into().unwrap();
        // Create signing key
        let signing_key = SigningKey::from_bytes(&secret_key_bytes.into()).unwrap();

        // Derive verifying key (public key)
        let verify_key = signing_key.verifying_key();

        // Get SEC1-encoded public key (uncompressed = 65 bytes)
        let pubkey_uncompressed: EncodedPoint = verify_key.to_encoded_point(false);
        let pubkey = VerifyingKey::from_encoded_point(&pubkey_uncompressed).unwrap();
        let (mut eip_191_signature, hash) = eip191_sign(msg, &secret_key_bytes);
        let recovered_pub_key =
            recover_pub_key_from_cast_sig_and_hash(&eip_191_signature, hash.as_slice());
        eip_191_signature.pop(); // drop last byte

        let signature = k256::ecdsa::Signature::from_slice(eip_191_signature.as_slice()).unwrap();

        assert_eq!(pubkey, recovered_pub_key);

        assert!(recovered_pub_key
            .verify_prehash(hash.as_slice(), &signature)
            .is_ok());
    }

    fn run() {
        let mut cast_pubkey = hex::decode(
        "9e20dd10239d4e3b5721d51d319418efd65e4d9832e3888ff4925466e52115dcb7eae23cdde649987956b2faf65a21d1203c1e8e0d38f0c1be4789c0456b4665",
    ).unwrap();

        let raw_hash =
            hex::decode("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap();

        // Add 4 prefix for uncompressed pubkey
        // cast returns the value without the tag
        // see: sec1 crate Tag
        cast_pubkey.insert(0, 4);

        let encoded_point = EncodedPoint::from_bytes(&cast_pubkey).unwrap();
        let pubkey = VerifyingKey::from_encoded_point(&encoded_point).unwrap();

        let mut cast_sig = hex::decode(
        "0b4fefcfe2bc874c86a5377d985ef61a3d32e65abb3589a593ef5919e3a20ef33bb815addedfce088e2a847fca3075052075673a79c8ee8bd60166e1489a256e1c",
    ).unwrap();

        let recovered_cast_pub_key = recover_pub_key_from_cast_sig_and_hash(&cast_sig, &raw_hash);

        // drop last byte
        cast_sig.pop();

        let signature = k256::ecdsa::Signature::from_slice(cast_sig.as_slice()).unwrap();

        // convert raw_hash to Digest without hashing

        println!(
            "Signature valid: {}",
            pubkey
                .verify_prehash(raw_hash.as_slice(), &signature)
                .is_ok()
        );

        assert_eq!(pubkey, recovered_cast_pub_key, "Public keys do not match");

        // ledger pubkey recovery from signature

        // anan
        let cast_sig_anan = hex::decode(
        "929a3fd4a6574cb9dc071d46598902daa2727164c1b3a12316dabfbbf501ee3250b3e59f30fba3bbc75fe67cc090e2655f89c468f970abf80bfdd135bc9f1d641c",
    ).unwrap();

        let anan_recovered_pubkey =
            recover_pub_key_from_cast_sig_and_hash(&cast_sig_anan, &msg_to_eip191_msg(b"anan"));

        println!(
            "Recovered public key: {}",
            hex::encode(anan_recovered_pubkey.to_sec1_bytes())
        );

        // baban
        let cast_sig_baban = hex::decode(
        "bebe2bd58f347396133e1beed0cd22a98541cc8819c2b2a5a9a64ff05e950f104e13d7a55d9482ed47a7f854862a244eecc9b0b6827cf6f2b4bc67372dff75fc1c"
    ).unwrap();

        let baban_recovered_pubkey =
            recover_pub_key_from_cast_sig_and_hash(&cast_sig_baban, &msg_to_eip191_msg(b"baban"));

        println!(
            "Baban recovered pubkey: {}",
            hex::encode(baban_recovered_pubkey.to_sec1_bytes())
        );

        assert_eq!(
            anan_recovered_pubkey, baban_recovered_pubkey,
            "recovered keys are not the same"
        );
    }

    fn recover_pub_key_from_cast_sig_and_msg(cast_sig: &[u8], msg: &[u8]) -> VerifyingKey {
        assert_eq!(cast_sig.len(), 65, "Invalid signature length");

        let y_odd = cast_sig[64] - 27;
        let y_odd = y_odd != 0;

        let signature = k256::ecdsa::Signature::from_slice(&cast_sig[0..64]).unwrap();

        VerifyingKey::recover_from_msg(msg, &signature, RecoveryId::new(y_odd, false))
            .expect("Failed to recover public key")
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

    fn msg_to_eip191_msg(msg: &[u8]) -> Vec<u8> {
        let mut eip191_msg = Vec::new();
        eip191_msg.extend_from_slice(b"\x19Ethereum Signed Message:\n");
        eip191_msg.extend_from_slice(msg.len().to_string().as_bytes());
        eip191_msg.extend_from_slice(msg);

        // eip191_msg

        // eip191_msg
        // keccak the msg
        keccak256(eip191_msg.as_slice()).to_vec()
    }

    /// Prefix + keccak according to EIP-191 "Ethereum Signed Message"
    fn eip191_prefixed_message(msg: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 64 + msg.len());
        out.extend_from_slice(b"\x19Ethereum Signed Message:\n");
        out.extend_from_slice(msg.len().to_string().as_bytes());
        out.extend_from_slice(msg);
        out
    }

    /// Sign a message with EIP-191 prefixing and return (sig65, hash32)
    /// - sig65: r(32) || s(32) || v(1) with v in {27, 28}
    /// - hash32: keccak256(prefix || len || msg)
    pub fn eip191_sign(msg: &[u8], secret_key_bytes: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        // Build the signing key

        let signing_key =
            SigningKey::from_bytes(secret_key_bytes.into()).expect("invalid secp256k1 secret key");

        use k256::ecdsa::signature::DigestSigner;
        use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};

        // EIP-191 prefixing, then keccak256
        let to_hash = eip191_prefixed_message(msg);
        let hash = sha2::Sha256::digest(&to_hash); // 32-byte digest
        let mut hasher = sha2::Sha256::new();
        hasher.update(&to_hash);

        // Sign the digest and get a RECOVERABLE signature (so we can emit v)
        let (rec_sig, recovery_id) = signing_key.sign_digest_recoverable(hasher).unwrap();

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
        hash32.copy_from_slice(&hash);

        (sig65, hash32)
    }
}
