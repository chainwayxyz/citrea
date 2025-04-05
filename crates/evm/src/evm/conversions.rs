use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_consensus::Transaction;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Bytes as RethBytes, PrimitiveSignature};
use reth_primitives::transaction::SignedTransactionIntoRecoveredExt;
use reth_primitives::{Recovered, TransactionSigned};
use revm::primitives::{AccountInfo as ReVmAccountInfo, TransactTo, TxEnv, U256};

use super::primitive_types::{RlpEvmTransaction, TransactionSignedAndRecovered};
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
        caller: tx.signer(),
        gas_limit: tx.gas_limit(),
        gas_price: U256::from(tx.effective_gas_price(None)),
        gas_priority_fee: tx.max_priority_fee_per_gas().map(U256::from),
        transact_to: to,
        value: tx.value(),
        data: RethBytes::from(tx.input().to_vec()),
        chain_id: tx.chain_id(),
        nonce: Some(tx.nonce()),
        access_list: tx.access_list().cloned().unwrap_or_default().0,
        // EIP-4844 related fields
        blob_hashes: tx.blob_versioned_hashes().unwrap_or_default().to_vec(),
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas().map(U256::from),
        authorization_list: tx
            .authorization_list()
            .map(|a| revm::primitives::AuthorizationList::Signed(a.to_vec())),
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
        // TODO: Use constant sys tx signature once we update reth
        let sys_tx_signature = PrimitiveSignature::new(U256::ZERO, U256::ZERO, false);
        if tx.signature() == &sys_tx_signature {
            return Ok(Self::new_unchecked(tx, SYSTEM_SIGNER));
        }
        tx.try_into_recovered()
            .map_err(|_| ConversionError::InvalidSignature)
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
) -> revm::primitives::BlockEnv {
    use revm::primitives::BlobExcessGasAndPrice;

    revm::primitives::BlockEnv {
        number: U256::from(sealed_header.number),
        coinbase: sealed_header.beneficiary,
        timestamp: U256::from(sealed_header.timestamp),
        prevrandao: Some(sealed_header.mix_hash),
        basefee: U256::from(sealed_header.base_fee_per_gas.unwrap_or_default()),
        gas_limit: U256::from(sealed_header.gas_limit),
        difficulty: U256::from(0),
        blob_excess_gas_and_price: sealed_header
            .excess_blob_gas
            .or(Some(0))
            .map(|gas| BlobExcessGasAndPrice::new(gas, true)),
    }
}
