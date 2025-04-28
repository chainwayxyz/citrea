/// If native feature is enabled, uses `tracing::info!` to log messages.
/// Otherwise, it falls back to `println!`.
/// This macro is useful for logging in both native and ZK environments.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        {
            #[cfg(feature = "native")]
            {
                ::tracing::info!($($arg)*)
            }
            #[cfg(not(feature = "native"))]
            {
                println!($($arg)*)
            }
        }
    };
}
