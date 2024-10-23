//! RISC0 Host helpers
use risc0_zkvm::ExecutorEnvBuilder;

#[cfg(not(feature = "bench"))]
/// Add benchmarking callbacks to the executor environment.
pub fn add_benchmarking_callbacks(env: &mut ExecutorEnvBuilder<'_>) {}

#[cfg(feature = "bench")]
/// Add benchmarking callbacks to the executor environment.
pub fn add_benchmarking_callbacks(env: &mut ExecutorEnvBuilder<'_>) {
    use sov_zk_cycle_utils::{cycle_count_callback, get_syscall_name, get_syscall_name_cycles};

    use crate::metrics::metrics_callback;

    let metrics_syscall_name = get_syscall_name();
    env.io_callback(metrics_syscall_name, metrics_callback);

    let cycles_syscall_name = get_syscall_name_cycles();
    env.io_callback(cycles_syscall_name, cycle_count_callback);
}
