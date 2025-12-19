use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_consensus::Transaction;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::Bytes as RethBytes;
#[cfg(feature = "native")]
use alloy_primitives::U256;
use ecrecover_address_provider::ECRECOVER_ADDRESS_PROVIDER;
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

impl TryFrom<RlpEvmTransaction> for Recovered<TransactionSigned> {
    type Error = ConversionError;

    fn try_from(evm_tx: RlpEvmTransaction) -> Result<Self, Self::Error> {
        let tx = TransactionSigned::try_from(evm_tx)?;
        if tx.signature() == &SYSTEM_SIGNATURE {
            return Ok(Self::new_unchecked(tx, SYSTEM_SIGNER));
        }

        #[cfg(not(feature = "native"))]
        {
            // Use pre-computed address from provider
            let address = ECRECOVER_ADDRESS_PROVIDER
                .get()
                .expect("Ecrecover address provider not initialized")
                .get_next()
                .expect("Missing ecrecover address in witness");

            return Ok(Self::new_unchecked(
                tx,
                alloy_primitives::Address::from(address),
            ));
        }

        #[cfg(feature = "native")]
        {
            tx.try_into_recovered()
                .map_err(|_| ConversionError::InvalidSignature)
        }
    }
}

/// Convert RlpEvmTransaction to Recovered<TransactionSigned>.
///
/// This function implements the ecrecover optimization pattern:
/// - On native: Performs actual ECDSA recovery and records the address to be added to input
/// - In non native: Uses pre-computed addresses from input
///
/// Addresses are recorded/consumed in deterministic order (block by block, tx by tx).
pub fn recover_raw_transaction(
    evm_tx: RlpEvmTransaction,
) -> Result<Recovered<TransactionSigned>, ConversionError> {
    let tx = TransactionSigned::try_from(evm_tx)?;
    if tx.signature() == &SYSTEM_SIGNATURE {
        return Ok(Recovered::new_unchecked(tx, SYSTEM_SIGNER));
    }

    #[cfg(not(feature = "native"))]
    {
        // Use pre-computed address from provider
        let address = ECRECOVER_ADDRESS_PROVIDER
            .get()
            .expect("Ecrecover address provider not initialized")
            .get_next()
            .expect("Missing ecrecover address in witness");

        return Ok(Recovered::new_unchecked(
            tx,
            alloy_primitives::Address::from(address),
        ));
    }

    #[cfg(feature = "native")]
    {
        let recovered = tx
            .try_into_recovered()
            .map_err(|_| ConversionError::InvalidSignature)?;

        // Record the address
        if let Some(provider) = ECRECOVER_ADDRESS_PROVIDER.get() {
            provider.record(recovered.signer().into_array());
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
