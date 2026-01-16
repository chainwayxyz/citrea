//! EIP-7966: eth_sendRawTransactionSync method
//! Description: A JSON-RPC method to reduce transaction submission latency
//! by allowing synchronous receipt of transaction hash and block inclusion.
//!
//! This module provides utilities for implementing EIP-7966, which submits
//! a signed raw transaction and waits synchronously for the transaction receipt
//! or a configurable timeout before returning.
//!
//! See: https://eips.ethereum.org/EIPS/eip-7966

use alloy_primitives::B256;
use jsonrpsee::types::ErrorObjectOwned;

/// EIP-7966 error code 4: Transaction was added to mempool but not processed within timeout.
pub const TIMEOUT_ERROR_CODE: i32 = 4;

/// EIP-7966 error code 5: Node is not ready to process the transaction or the transaction is erroneous.
pub const UNREADY_ERROR_CODE: i32 = 5;

/// Default timeout in milliseconds. (2secs)
pub const DEFAULT_TIMEOUT_MS: u64 = 2_000;

/// Creates an EIP-7966 timeout error (code 4).
///
/// Returned when the transaction was added to the mempool but wasn't
/// processed within the specified timeout period.
///
/// # Arguments
/// * `hash` - The transaction hash that was submitted
/// * `timeout_ms` - The timeout that was used (in milliseconds)
pub fn timeout_error(hash: B256, timeout_ms: u64) -> ErrorObjectOwned {
    let timeout_secs = timeout_ms as f64 / 1000.0;
    ErrorObjectOwned::owned(
        TIMEOUT_ERROR_CODE,
        format!(
            "The transaction was added to the mempool but wasn't processed in {timeout_secs}s."
        ),
        Some(hash),
    )
}

/// Creates an EIP-7966 unreadiness error (code 5).
///
/// Returned when the processing node is not ready to accept a new transaction or the transaction is erroneous.
///
/// # Arguments
/// * `reason` - Unreadiness error string
/// * `hash` - Optional transaction hash if the transaction was successfully submitted
pub fn unready_error(reason: &str, hash: Option<B256>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(UNREADY_ERROR_CODE, reason.to_string(), hash)
}

/// Calculates the effective timeout
///
/// - If `None`, returns `DEFAULT_TIMEOUT_MS`
/// - If `Some(0)` returns `DEFAULT_TIMEOUT_MS`
/// - Otherwise, returns the minimum of the requested value and `max_timeout_ms`
///
/// # Arguments
/// * `requested_ms` - Optional timeout duration in milliseconds
/// * `max_timeout_ms` - Maximum allowed timeout in milliseconds
pub fn calculate_timeout_ms(requested_ms: Option<u64>, max_timeout_ms: u64) -> u64 {
    match requested_ms {
        Some(ms) if ms > 0 => std::cmp::min(ms, max_timeout_ms),
        _ => DEFAULT_TIMEOUT_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_error() {
        let hash = B256::ZERO;
        let err = timeout_error(hash, 5000);

        assert_eq!(err.code(), TIMEOUT_ERROR_CODE);
        assert!(err.message().contains("5s"));
        assert!(err.message().contains("wasn't processed"));
    }

    #[test]
    fn test_unready_error_with_hash() {
        let hash = B256::ZERO;
        let err = unready_error("Test reason", Some(hash));

        assert_eq!(err.code(), UNREADY_ERROR_CODE);
        assert_eq!(err.message(), "Test reason");
    }

    #[test]
    fn test_unready_error_without_hash() {
        let err = unready_error("No hash provided", None);

        assert_eq!(err.code(), UNREADY_ERROR_CODE);
        assert_eq!(err.message(), "No hash provided");
    }

    #[test]
    fn test_calculate_timeout_custom_max() {
        // Custom max of 30 seconds
        assert_eq!(calculate_timeout_ms(Some(50_000), 30_000), 30_000);
        assert_eq!(calculate_timeout_ms(Some(20_000), 30_000), 20_000);
    }
}
