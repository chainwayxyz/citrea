//! Helpers for mapping L1 blocks to light-client prover state versions.

/// Returns the LCP JMT pre-state version required to process `l1_height`.
///
/// The light-client prover commits one JMT version per processed L1 block. Therefore
/// the initial DA block starts from version 0, and each following L1 block starts
/// from the version committed by the previous L1 block.
pub(crate) fn lcp_pre_state_version(initial_da_height: u64, l1_height: u64) -> anyhow::Result<u64> {
    ensure_l1_height_at_or_after_initial_da_height(initial_da_height, l1_height)?;

    Ok(l1_height - initial_da_height)
}

/// Ensures that `l1_height` is not before the configured initial DA height.
fn ensure_l1_height_at_or_after_initial_da_height(
    initial_da_height: u64,
    l1_height: u64,
) -> anyhow::Result<()> {
    if l1_height < initial_da_height {
        anyhow::bail!(
            "Cannot build light client input for L1 block #{} before initial DA height #{}",
            l1_height,
            initial_da_height
        );
    }

    Ok(())
}

/// Validates that `l1_height` is the next L1 block expected by live proving.
pub(crate) fn validate_live_l1_height(
    initial_da_height: u64,
    last_scanned_l1_height: Option<u64>,
    l1_height: u64,
) -> anyhow::Result<()> {
    ensure_l1_height_at_or_after_initial_da_height(initial_da_height, l1_height)?;

    let Some(last_scanned_l1_height) = last_scanned_l1_height else {
        if l1_height != initial_da_height {
            anyhow::bail!(
                "Cannot build light client input for L1 block #{} before initial L1 block #{} has been processed",
                l1_height,
                initial_da_height
            );
        }

        return Ok(());
    };

    let expected_next_l1_height = last_scanned_l1_height + 1;
    if l1_height != expected_next_l1_height {
        anyhow::bail!(
            "Live light client processing expected L1 block #{}, got #{}",
            expected_next_l1_height,
            l1_height
        );
    }

    Ok(())
}

/// Validates that `l1_height` can be used to build a read-only RPC input.
pub(crate) fn validate_rpc_l1_height(
    initial_da_height: u64,
    last_scanned_l1_height: Option<u64>,
    l1_height: u64,
) -> anyhow::Result<()> {
    ensure_l1_height_at_or_after_initial_da_height(initial_da_height, l1_height)?;

    if let Some(last_scanned_l1_height) = last_scanned_l1_height {
        let max_request_height = last_scanned_l1_height + 1;
        if l1_height > max_request_height {
            anyhow::bail!(
                "Cannot build light client input for future L1 block #{}; last scanned L1 block is #{}",
                l1_height,
                last_scanned_l1_height
            );
        }
    } else if l1_height != initial_da_height {
        anyhow::bail!(
            "Cannot build light client input for L1 block #{} before initial L1 block #{} has been processed",
            l1_height,
            initial_da_height
        );
    }

    Ok(())
}
