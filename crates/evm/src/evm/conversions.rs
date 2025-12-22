use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_consensus::{SignableTransaction, Transaction};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::Bytes as RethBytes;
#[cfg(feature = "native")]
use alloy_primitives::U256;
use recovered_pubkey_provider::RECOVERED_PUBKEY_PROVIDER;
use reth_primitives::{Recovered, TransactionSigned};
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

impl TryFrom<RlpEvmTransaction> for Recovered<TransactionSigned> {
    type Error = ConversionError;

    fn try_from(evm_tx: RlpEvmTransaction) -> Result<Self, Self::Error> {
        let tx = TransactionSigned::try_from(evm_tx)?;
        if tx.signature() == &SYSTEM_SIGNATURE {
            return Ok(Self::new_unchecked(tx, SYSTEM_SIGNER));
        }

        tx.try_into_recovered()
            .map_err(|_| ConversionError::InvalidSignature)
    }
}

/// Convert RlpEvmTransaction to Recovered<TransactionSigned>.
///
/// This function implements the ecrecover optimization pattern:
/// - On native: Performs actual ecrecover and records the pubkey to be added to input
/// - In non native: Uses pre-computed pubkeys from input to verify and derive address
///
/// Pubkeys are recorded/consumed in deterministic order (block by block, tx by tx).
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
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::VerifyingKey;
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        // Use pre-computed pubkey from provider
        let pubkey_bytes = RECOVERED_PUBKEY_PROVIDER
            .get()
            .expect("Ecrecover pubkey provider not initialized")
            .get_next()
            .expect("Missing ecrecover pubkey in witness");

        let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
            .map_err(|_| ConversionError::InvalidSignature)?;

        let sig = *tx.signature();
        let prehash = tx.signature_hash();

        let normalized_sig = sig.normalized_s();
        let k256_sig = normalized_sig
            .to_k256()
            .map_err(|_| ConversionError::InvalidSignature)?;

        verifying_key
            .verify_prehash(prehash.as_slice(), &k256_sig)
            .map_err(|_| ConversionError::InvalidSignature)?;

        // Compute address from pubkey
        let affine = verifying_key.as_ref();
        let encoded = affine.to_encoded_point(false);
        let digest = keccak256(&encoded.as_bytes()[1..]);
        let address = Address::from_slice(&digest[12..]);

        return Ok(Recovered::new_unchecked(tx, Address::from(address)));
    }

    #[cfg(feature = "native")]
    {
        let sig = *tx.signature();
        let prehash = *tx.signature_hash();

        let recovered = tx
            .try_into_recovered()
            .map_err(|_| ConversionError::InvalidSignature)?;

        let normalized_sig = sig.normalized_s();
        let verifying_key = k256::ecdsa::VerifyingKey::recover_from_prehash(
            prehash.as_slice(),
            &normalized_sig.to_k256().unwrap(),
            normalized_sig.recid(),
        )
        .map_err(|_| ConversionError::InvalidSignature)?;

        let encoded = verifying_key.to_sec1_bytes();

        // Record the pubkey
        if let Some(provider) = RECOVERED_PUBKEY_PROVIDER.get() {
            provider.record(encoded.to_vec());
        }

        Ok(recovered)
    }
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
