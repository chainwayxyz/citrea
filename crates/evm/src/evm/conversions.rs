use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::Bytes as RethBytes;
use reth_primitives::{
    TransactionSigned, TransactionSignedEcRecovered, TransactionSignedNoHash, KECCAK_EMPTY,
};
use revm::primitives::{AccountInfo as ReVmAccountInfo, SpecId, TransactTo, TxEnv, U256};

use super::primitive_types::{RlpEvmTransaction, TransactionSignedAndRecovered};
use super::AccountInfo;

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

pub(crate) fn create_tx_env(tx: &TransactionSignedEcRecovered, spec_id: SpecId) -> TxEnv {
    let to = match tx.to() {
        Some(addr) => TransactTo::Call(addr),
        None => TransactTo::Create,
    };

    let mut tx_env = TxEnv {
        caller: tx.signer(),
        gas_limit: tx.gas_limit(),
        gas_price: U256::from(tx.effective_gas_price(None)),
        gas_priority_fee: tx.max_priority_fee_per_gas().map(U256::from),
        transact_to: to,
        value: tx.value(),
        data: RethBytes::from(tx.input().to_vec()),
        chain_id: tx.chain_id(),
        nonce: Some(tx.nonce()),
        access_list: vec![],
        // EIP-4844 related fields
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        blob_hashes: vec![],
        max_fee_per_blob_gas: None,
        authorization_list: None,
    };

    if spec_id >= SpecId::CANCUN {
        // A bug was found before activating cancun
        // Access list supplied with txs were ignored
        // that's why we can only use the access list if spec >= cancun
        tx_env.access_list = tx.access_list().cloned().unwrap_or_default().0;

        // EIP-4844 related fields
        tx_env.blob_hashes = tx.blob_versioned_hashes().unwrap_or_default();
        tx_env.max_fee_per_blob_gas = tx.max_fee_per_blob_gas().map(U256::from);
    }

    tx_env
}

#[derive(Debug, PartialEq, Clone)]
pub enum ConversionError {
    EmptyRawTransactionData,
    FailedToDecodeSignedTransaction,
}

impl TryFrom<RlpEvmTransaction> for TransactionSignedNoHash {
    type Error = ConversionError;

    fn try_from(data: RlpEvmTransaction) -> Result<Self, Self::Error> {
        let data = RethBytes::from(data.rlp);
        if data.is_empty() {
            return Err(ConversionError::EmptyRawTransactionData);
        }

        // According to this pr: https://github.com/paradigmxyz/reth/pull/11218
        // decode_enveloped -> decode_2718
        let transaction = TransactionSigned::decode_2718(&mut data.as_ref())
            .map_err(|_| ConversionError::FailedToDecodeSignedTransaction)?;

        Ok(transaction.into())
    }
}

impl TryFrom<RlpEvmTransaction> for TransactionSignedEcRecovered {
    type Error = ConversionError;

    fn try_from(evm_tx: RlpEvmTransaction) -> Result<Self, Self::Error> {
        let tx = TransactionSignedNoHash::try_from(evm_tx)?;
        let tx: TransactionSigned = tx.into();
        let tx = tx
            .into_ecrecovered()
            .ok_or(ConversionError::FailedToDecodeSignedTransaction)?;

        Ok(tx)
    }
}

impl From<TransactionSignedAndRecovered> for TransactionSignedEcRecovered {
    fn from(value: TransactionSignedAndRecovered) -> Self {
        TransactionSignedEcRecovered::from_signed_transaction(
            value.signed_transaction,
            value.signer,
        )
    }
}

#[cfg(feature = "native")]
pub(crate) fn sealed_block_to_block_env(
    sealed_header: &reth_primitives::SealedHeader,
) -> revm::primitives::BlockEnv {
    use citrea_primitives::forks::FORKS;
    use revm::primitives::BlobExcessGasAndPrice;
    use sov_modules_api::fork::fork_from_block_number;

    use crate::citrea_spec_id_to_evm_spec_id;

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
            .or_else(|| {
                if citrea_spec_id_to_evm_spec_id(
                    fork_from_block_number(FORKS, sealed_header.number).spec_id,
                ) >= SpecId::CANCUN
                {
                    Some(0)
                } else {
                    None
                }
            })
            .map(BlobExcessGasAndPrice::new),
    }
}
