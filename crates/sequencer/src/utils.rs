//! Commonly used code snippets

use alloy_primitives::Bytes;
use alloy_rlp::Decodable;
use reth_primitives::{PooledTransactionsElement, PooledTransactionsElementEcRecovered};
use reth_rpc_eth_types::error::{EthApiError, EthResult};

/// Recovers a [PooledTransactionsElementEcRecovered] from an enveloped encoded byte stream.
///
/// See [PooledTransactionsElement::decode_enveloped]
pub(crate) fn recover_raw_transaction(
    data: Bytes,
) -> EthResult<PooledTransactionsElementEcRecovered> {
    if data.is_empty() {
        return Err(EthApiError::EmptyRawTransactionData);
    }

    let transaction = PooledTransactionsElement::decode(&mut data.as_ref())
        .map_err(|_| EthApiError::FailedToDecodeSignedTransaction)?;

    transaction
        .try_into_ecrecovered()
        .or(Err(EthApiError::InvalidTransactionSignature))
}
