use reth_primitives::{
    Bytes as RethBytes, TransactionSigned, TransactionSignedEcRecovered, TransactionSignedNoHash,
    KECCAK_EMPTY,
};
use revm::primitives::{
    AccountInfo as ReVmAccountInfo, BlockEnv as ReVmBlockEnv, CreateScheme, TransactTo, TxEnv, U256,
};

use super::primitive_types::{BlockEnv, RlpEvmTransaction, TransactionSignedAndRecovered};
use super::AccountInfo;

impl From<AccountInfo> for ReVmAccountInfo {
    fn from(info: AccountInfo) -> Self {
        Self {
            nonce: info.nonce,
            balance: info.balance,
            code: None,
            code_hash: info.code_hash,
        }
    }
}

impl From<ReVmAccountInfo> for AccountInfo {
    fn from(info: ReVmAccountInfo) -> Self {
        Self {
            balance: info.balance,
            code_hash: info.code_hash,
            nonce: info.nonce,
        }
    }
}

impl From<AccountInfo> for reth_primitives::Account {
    fn from(acc: AccountInfo) -> Self {
        Self {
            balance: acc.balance,
            bytecode_hash: if acc.code_hash == KECCAK_EMPTY {
                None
            } else {
                Some(acc.code_hash)
            },
            nonce: acc.nonce,
        }
    }
}

impl From<BlockEnv> for ReVmBlockEnv {
    fn from(block_env: BlockEnv) -> Self {
        Self {
            number: U256::from(block_env.number),
            coinbase: block_env.coinbase,
            timestamp: U256::from(block_env.timestamp),
            difficulty: U256::ZERO,
            prevrandao: Some(block_env.prevrandao),
            basefee: U256::from(block_env.basefee),
            gas_limit: U256::from(block_env.gas_limit),
            // EIP-4844 related field
            // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
            blob_excess_gas_and_price: None,
        }
    }
}

pub(crate) fn create_tx_env(tx: &TransactionSignedEcRecovered) -> TxEnv {
    let to = match tx.to() {
        Some(addr) => TransactTo::Call(addr),
        None => TransactTo::Create(CreateScheme::Create),
    };

    TxEnv {
        caller: tx.signer(),
        gas_limit: tx.gas_limit(),
        gas_price: U256::from(tx.effective_gas_price(None)),
        gas_priority_fee: tx.max_priority_fee_per_gas().map(U256::from),
        transact_to: to,
        value: tx.value(),
        data: RethBytes::from(tx.input().to_vec()),
        chain_id: tx.chain_id(),
        nonce: Some(tx.nonce()),
        // TODO handle access list
        access_list: vec![],
        // EIP-4844 related fields
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        blob_hashes: vec![],
        max_fee_per_blob_gas: None,
    }
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

        let transaction = TransactionSigned::decode_enveloped(&mut data.as_ref())
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
