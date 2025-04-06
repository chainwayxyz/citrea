use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};
use revm_precompile::{
    u64_to_address, Bytes, Precompile, PrecompileError, PrecompileOutput, PrecompileResult,
    PrecompileWithAddress, B256,
};

// Benchmarks show that the zk cycle counts for schorr verification is
// %33 more than p256r1 verification. So we set the base gas cost
// to be 4600 as 4600 ~ 1.33 * 3450 (p256r1 base gas cost).
const SCHNORRVERIFY_BASE: u64 = 4600;
/// Precompile for verifying Schnorr signatures.
pub const SCHNORRVERIFY: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(0x200), Precompile::Standard(schnorr_verify));

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
        return Err(PrecompileError::OutOfGas.into());
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
    use secp256k1::{Keypair, Message, XOnlyPublicKey, SECP256K1};

    use super::*;

    const TRUE_32_BYTES: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    fn random_signature() -> (XOnlyPublicKey, Message, secp256k1::schnorr::Signature) {
        let keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let message = Message::from_digest_slice(&[1; 32]).unwrap();
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

        let mut raw_sig = signature.serialize();
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
            Err(PrecompileError::OutOfGas.into())
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
