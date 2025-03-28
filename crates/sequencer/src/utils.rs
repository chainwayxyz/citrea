//! Commonly used code snippets

use alloy_network::eip2718::Decodable2718;
use alloy_primitives::Bytes;
use reth_primitives::transaction::SignedTransaction;
use reth_primitives::{PooledTransaction, Recovered};
use reth_rpc_eth_types::error::{EthApiError, EthResult};

/// Recovers a [PooledTransactionsElementEcRecovered] from an enveloped encoded byte stream.
///
/// See [PooledTransactionsElement::decode_enveloped]
pub(crate) fn recover_raw_transaction(data: Bytes) -> EthResult<Recovered<PooledTransaction>> {
    if data.is_empty() {
        return Err(EthApiError::EmptyRawTransactionData);
    }

    let transaction: PooledTransaction = Decodable2718::decode_2718(&mut data.as_ref())
        .map_err(|_| EthApiError::FailedToDecodeSignedTransaction)?;

    transaction
        .try_into_recovered()
        .or(Err(EthApiError::InvalidTransactionSignature))
}
