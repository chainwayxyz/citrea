use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_consensus::{SignableTransaction, Transaction};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::Bytes as RethBytes;
#[cfg(feature = "native")]
use alloy_primitives::U256;
#[cfg(feature = "native")]
use recovered_pubkey_provider::Secp256k1Pubkey;
#[cfg(not(feature = "native"))]
use recovered_pubkey_provider::RECOVERED_PUBKEY_PROVIDER;
use reth_primitives::{Recovered, TransactionSigned};
#[cfg(feature = "native")]
use reth_primitives_traits::SignedTransaction;
use revm::context::{TransactTo, TxEnv};
use revm::state::AccountInfo as ReVmAccountInfo;

use super::primitive_types::{
    CitreaReceiptWithBloom, RlpEvmTransaction, TransactionSignedAndRecovered,
};
use super::system_events::SYSTEM_SIGNATURE;
use super::AccountInfo;
use crate::SYSTEM_SIGNER;

impl From<AccountInfo> for ReVmAccountInfo {
    fn from(info: AccountInfo) -> Self {
        Self {
            nonce: info.nonce,
            balance: info.balance,
            code: None,
            code_hash: info.code_hash.unwrap_or(KECCAK_EMPTY),
        }
    }
}

impl From<ReVmAccountInfo> for AccountInfo {
    fn from(info: ReVmAccountInfo) -> Self {
        let code_hash = if info.code_hash != KECCAK_EMPTY {
            Some(info.code_hash)
        } else {
            None
        };
        Self {
            balance: info.balance,
            code_hash,
            nonce: info.nonce,
        }
    }
}

impl From<AccountInfo> for reth_primitives::Account {
    fn from(acc: AccountInfo) -> Self {
        Self {
            balance: acc.balance,
            bytecode_hash: acc.code_hash,
            nonce: acc.nonce,
        }
    }
}

pub(crate) fn create_tx_env(tx: &Recovered<TransactionSigned>) -> TxEnv {
    let to = match tx.to() {
        Some(addr) => TransactTo::Call(addr),
        None => TransactTo::Create,
    };

    let tx_env = TxEnv {
        tx_type: tx.tx_type() as u8,
        caller: tx.signer(),
        gas_limit: tx.gas_limit(),
        gas_price: tx.effective_gas_price(None),
        gas_priority_fee: tx.max_priority_fee_per_gas(),
        kind: to,
        value: tx.value(),
        data: RethBytes::from(tx.input().to_vec()),
        chain_id: tx.chain_id(),
        nonce: tx.nonce(),
        access_list: tx.access_list().cloned().unwrap_or_default(),
        // EIP-4844 related fields
        blob_hashes: tx.blob_versioned_hashes().unwrap_or_default().to_vec(),
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas().unwrap_or_default(),
        authorization_list: tx.authorization_list().unwrap_or_default().to_vec(),
    };

    tx_env
}

#[derive(Debug, PartialEq, Clone)]
pub enum ConversionError {
    EmptyRawTransactionData,
    FailedToDecodeSignedTransaction,
    InvalidSignature,
}

impl TryFrom<RlpEvmTransaction> for TransactionSigned {
    type Error = ConversionError;

    fn try_from(data: RlpEvmTransaction) -> Result<Self, Self::Error> {
        let data = RethBytes::from(data.rlp);
        if data.is_empty() {
            return Err(ConversionError::EmptyRawTransactionData);
        }

        // According to this pr: https://github.com/paradigmxyz/reth/pull/11218
        // decode_enveloped -> decode_2718
        TransactionSigned::decode_2718(&mut data.as_ref())
            .map_err(|_| ConversionError::FailedToDecodeSignedTransaction)
    }
}

#[cfg(any(test, not(feature = "native")))]
fn verify_prehash_with_recovery_parity(
    verifying_key: &k256::ecdsa::VerifyingKey,
    signature: &k256::ecdsa::Signature,
    prehash: &[u8],
    expected_y_parity: bool,
) -> Result<(), ConversionError> {
    use k256::elliptic_curve::bigint::U256 as K256U256;
    use k256::elliptic_curve::group::prime::PrimeCurveAffine;
    use k256::elliptic_curve::ops::{Invert, LinearCombination, Reduce};
    use k256::elliptic_curve::point::AffineCoordinates;
    use k256::elliptic_curve::scalar::IsHigh;
    use k256::{FieldBytes, ProjectivePoint, Scalar};

    if prehash.len() != FieldBytes::default().len() || bool::from(signature.s().is_high()) {
        return Err(ConversionError::InvalidSignature);
    }

    let prehash = FieldBytes::from_slice(prehash);
    let z = <Scalar as Reduce<K256U256>>::reduce_bytes(prehash);
    let (r, s) = signature.split_scalars();
    let s_inv = *s.invert_vartime();
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    let q = ProjectivePoint::from(*verifying_key.as_affine());

    let verification_point =
        ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &u1, &q, &u2).to_affine();

    if bool::from(verification_point.is_identity())
        || verification_point.x() != FieldBytes::from(r)
        || bool::from(verification_point.y_is_odd()) != expected_y_parity
    {
        return Err(ConversionError::InvalidSignature);
    }

    Ok(())
}

/// Convert RlpEvmTransaction to Recovered<TransactionSigned>.
///
/// This function implements the ecrecover optimization pattern:
/// - On native: Performs the standard ecrecover.
/// - In non native: Uses pre-computed pubkeys from input to verify and derive address.
///
/// In the circuit, pubkeys are consumed in deterministic order (block by block,
/// tx by tx). The batch prover collects those same pubkeys out of band via
/// [`recover_pubkey`], replaying transactions in the same order.
pub fn recover_raw_transaction(
    evm_tx: RlpEvmTransaction,
) -> Result<Recovered<TransactionSigned>, ConversionError> {
    let tx = TransactionSigned::try_from(evm_tx)?;
    if tx.signature() == &SYSTEM_SIGNATURE {
        return Ok(Recovered::new_unchecked(tx, SYSTEM_SIGNER));
    }

    #[cfg(not(feature = "native"))]
    {
        use alloy_primitives::{keccak256, Address};
        use k256::ecdsa::VerifyingKey;
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        // The batch-proof circuit feeds pre-computed pubkeys.
        let provider = RECOVERED_PUBKEY_PROVIDER
            .get()
            .expect("RECOVERED_PUBKEY_PROVIDER should be set");
        let pubkey_bytes = provider
            .get_next()
            .expect("Missing ecrecover pubkey in witness");

        let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
            .map_err(|_| ConversionError::InvalidSignature)?;

        let sig = *tx.signature();
        let prehash = tx.signature_hash();

        let k256_sig = sig
            .to_k256()
            .map_err(|_| ConversionError::InvalidSignature)?;

        verify_prehash_with_recovery_parity(
            &verifying_key,
            &k256_sig,
            prehash.as_slice(),
            sig.recid().is_y_odd(),
        )?;

        // Compute address from pubkey
        let encoded = verifying_key.as_ref().to_encoded_point(false);
        let digest = keccak256(&encoded.as_bytes()[1..]);
        let address = Address::from_slice(&digest[12..]);

        Ok(Recovered::new_unchecked(tx, address))
    }

    #[cfg(feature = "native")]
    {
        tx.try_into_recovered()
            .map_err(|_| ConversionError::InvalidSignature)
    }
}

/// Recover the uncompressed secp256k1 pubkey for a user transaction.
///
/// Returns `None` for system transactions, which carry the sentinel system
/// signature and are not ecrecovered (they consume no pubkey in the circuit).
///
/// The batch prover uses this to collect the pubkeys handed to the batch-proof
/// circuit as witness data. It must be called in the same deterministic order
/// the circuit consumes them (block by block, tx by tx). The low-s rejection
/// here mirrors both the non-native verifier and the standard
/// `try_into_recovered` path so the collected pubkey always matches the one the
/// circuit verifies.
#[cfg(feature = "native")]
pub fn recover_pubkey(
    evm_tx: RlpEvmTransaction,
) -> Result<Option<Secp256k1Pubkey>, ConversionError> {
    use k256::elliptic_curve::scalar::IsHigh;

    let tx = TransactionSigned::try_from(evm_tx)?;
    if tx.signature() == &SYSTEM_SIGNATURE {
        return Ok(None);
    }

    let sig = *tx.signature();
    let prehash = *tx.signature_hash();

    let k256_sig = sig
        .to_k256()
        .map_err(|_| ConversionError::InvalidSignature)?;

    // Reject high-s signatures to match the non-native verifier and the
    // standard `try_into_recovered` path.
    if bool::from(k256_sig.s().is_high()) {
        return Err(ConversionError::InvalidSignature);
    }

    let verifying_key =
        k256::ecdsa::VerifyingKey::recover_from_prehash(prehash.as_slice(), &k256_sig, sig.recid())
            .map_err(|_| ConversionError::InvalidSignature)?;

    let pubkey: Secp256k1Pubkey = verifying_key
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .expect("secp256k1 uncompressed pubkey must be 65 bytes");

    Ok(Some(pubkey))
}

impl From<TransactionSignedAndRecovered> for Recovered<TransactionSigned> {
    fn from(value: TransactionSignedAndRecovered) -> Self {
        Self::new_unchecked(value.signed_transaction, value.signer)
    }
}

#[cfg(feature = "native")]
pub(crate) fn sealed_block_to_block_env(
    sealed_header: &reth_primitives::SealedHeader,
) -> revm::context::BlockEnv {
    use citrea_primitives::forks::fork_from_block_number;
    use revm::context_interface::block::BlobExcessGasAndPrice;
    use revm::primitives::hardfork::SpecId::PRAGUE;

    use crate::citrea_spec_id_to_evm_spec_id;
    let evm_spec_id =
        citrea_spec_id_to_evm_spec_id(fork_from_block_number(sealed_header.number).spec_id);
    revm::context::BlockEnv {
        number: sealed_header.number,
        beneficiary: sealed_header.beneficiary,
        timestamp: sealed_header.timestamp,
        prevrandao: Some(sealed_header.mix_hash),
        basefee: sealed_header.base_fee_per_gas.unwrap_or_default(),
        gas_limit: sealed_header.gas_limit,
        difficulty: U256::from(0),
        blob_excess_gas_and_price: sealed_header
            .excess_blob_gas
            .or(Some(0))
            .map(|gas| BlobExcessGasAndPrice::new(gas, evm_spec_id.is_enabled_in(PRAGUE))),
    }
}

/// Converts CitreaReceiptWithBloom to Reth Receipt
impl From<&CitreaReceiptWithBloom> for reth_primitives::Receipt {
    fn from(receipt: &CitreaReceiptWithBloom) -> Self {
        receipt.receipt.receipt.clone()
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;
    use k256::FieldBytes;

    use super::*;

    #[test]
    fn ecdsa_witness_pubkey_must_match_recovery_parity() {
        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let verifying_key = *signing_key.verifying_key();
        let prehash = [2u8; 32];
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&prehash).unwrap();

        verify_prehash_with_recovery_parity(
            &verifying_key,
            &signature,
            &prehash,
            recovery_id.is_y_odd(),
        )
        .unwrap();

        assert_eq!(
            verify_prehash_with_recovery_parity(
                &verifying_key,
                &signature,
                &prehash,
                !recovery_id.is_y_odd(),
            ),
            Err(ConversionError::InvalidSignature)
        );
    }

    #[test]
    fn ecdsa_witness_pubkey_rejects_high_s_signature() {
        let signing_key = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let verifying_key = *signing_key.verifying_key();
        let prehash = [4u8; 32];
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&prehash).unwrap();
        let high_s_signature = k256::ecdsa::Signature::from_scalars(
            FieldBytes::from(signature.r()),
            FieldBytes::from(-signature.s()),
        )
        .unwrap();

        assert_eq!(
            verify_prehash_with_recovery_parity(
                &verifying_key,
                &high_s_signature,
                &prehash,
                recovery_id.is_y_odd(),
            ),
            Err(ConversionError::InvalidSignature)
        );
    }

    #[cfg(feature = "native")]
    #[test]
    fn native_recovery_rejects_high_s_transaction() {
        use alloy::consensus::{SignableTransaction, TxEnvelope};
        use alloy::providers::network::TxSignerSync;
        use alloy::signers::local::PrivateKeySigner;
        use alloy_eips::eip2718::Encodable2718;
        use alloy_primitives::{Address, Bytes, PrimitiveSignature, U256};
        use alloy_rpc_types::{TransactionInput, TransactionRequest};

        const SECP256K1N_ORDER: U256 = U256::from_be_bytes([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ]);

        let wallet = "dcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
            .parse::<PrivateKeySigner>()
            .unwrap();
        let mut request = TransactionRequest::default()
            .from(wallet.address())
            .nonce(0u64)
            .max_priority_fee_per_gas(1)
            .max_fee_per_gas(1)
            .gas_limit(21_000)
            .to(Address::repeat_byte(2))
            .value(U256::from(1u64))
            .input(TransactionInput::new(Bytes::new()));
        request.chain_id = Some(1);

        let typed_tx = request.build_typed_tx().unwrap();
        let mut tx = typed_tx.eip1559().unwrap().clone();
        let sig = wallet.sign_transaction_sync(&mut tx).unwrap();

        let envelope: TxEnvelope = tx.clone().into_signed(sig).into();
        let mut valid_bytes = Vec::new();
        envelope.encode_2718(&mut valid_bytes);
        recover_raw_transaction(RlpEvmTransaction {
            rlp: valid_bytes.clone(),
        })
        .unwrap();

        let high_s_sig = PrimitiveSignature::new(sig.r(), SECP256K1N_ORDER - sig.s(), !sig.v());
        let envelope: TxEnvelope = tx.into_signed(high_s_sig).into();

        let mut high_s_bytes = Vec::new();
        envelope.encode_2718(&mut high_s_bytes);

        // `recover_raw_transaction`: `try_into_recovered` enforces low-s.
        assert!(matches!(
            recover_raw_transaction(RlpEvmTransaction {
                rlp: high_s_bytes.clone()
            }),
            Err(ConversionError::FailedToDecodeSignedTransaction
                | ConversionError::InvalidSignature)
        ));

        // `recover_pubkey` (the batch prover's second pass) applies an explicit
        // low-s check so it agrees with `recover_raw_transaction`.
        recover_pubkey(RlpEvmTransaction { rlp: valid_bytes })
            .unwrap()
            .expect("user tx must yield a pubkey");
        assert!(matches!(
            recover_pubkey(RlpEvmTransaction { rlp: high_s_bytes }),
            Err(ConversionError::FailedToDecodeSignedTransaction
                | ConversionError::InvalidSignature)
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn native_recovery_paths_agree_on_signer() {
        use alloy::consensus::{SignableTransaction, TxEnvelope};
        use alloy::providers::network::TxSignerSync;
        use alloy::signers::local::PrivateKeySigner;
        use alloy_eips::eip2718::Encodable2718;
        use alloy_primitives::{keccak256, Address, Bytes, U256};
        use alloy_rpc_types::{TransactionInput, TransactionRequest};

        let wallet = "dcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
            .parse::<PrivateKeySigner>()
            .unwrap();
        let mut request = TransactionRequest::default()
            .from(wallet.address())
            .nonce(0u64)
            .max_priority_fee_per_gas(1)
            .max_fee_per_gas(1)
            .gas_limit(21_000)
            .to(Address::repeat_byte(2))
            .value(U256::from(1u64))
            .input(TransactionInput::new(Bytes::new()));
        request.chain_id = Some(1);

        let typed_tx = request.build_typed_tx().unwrap();
        let mut tx = typed_tx.eip1559().unwrap().clone();
        let sig = wallet.sign_transaction_sync(&mut tx).unwrap();
        let envelope: TxEnvelope = tx.into_signed(sig).into();
        let mut bytes = Vec::new();
        envelope.encode_2718(&mut bytes);

        let recovered = recover_raw_transaction(RlpEvmTransaction { rlp: bytes.clone() })
            .unwrap()
            .signer();
        assert_eq!(recovered, wallet.address());

        // The second-pass pubkey recovery must derive the same signer.
        let pubkey = recover_pubkey(RlpEvmTransaction { rlp: bytes })
            .unwrap()
            .expect("user tx must yield a pubkey");
        let address = Address::from_slice(&keccak256(&pubkey[1..])[12..]);
        assert_eq!(address, wallet.address());
    }
}
