#[macro_export]
macro_rules! log_result_or_error {
    ($tables_group:literal, $call:expr) => {{
        match $call {
            Ok(result) => {
                tracing::debug!("Deleted {} records from {} group", result, $tables_group);
            }
            Err(e) => {
                tracing::error!(
                    "Failed to prune ledger's {} table group: {:?}",
                    $tables_group,
                    e
                );
                return;
            }
        }
    }};
}
