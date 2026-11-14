//! Session statistics shared by local execution and network proving.
use metrics::gauge;
use sov_rollup_interface::zk::Sp1ExecutionStats;
use sp1_sdk::ExecutionReport;

/// Session statistics of an execution run with gas calculation.
pub(crate) fn execution_stats(report: &ExecutionReport) -> anyhow::Result<Sp1ExecutionStats> {
    Ok(Sp1ExecutionStats {
        instruction_count: report.total_instruction_count(),
        syscall_count: report.total_syscall_count(),
        gas: report
            .gas()
            .ok_or_else(|| anyhow::anyhow!("SP1 executor reported no gas"))?,
    })
}

pub(crate) fn record_execution(stats: &Sp1ExecutionStats) {
    gauge!("sp1_execution_instruction_count").set(stats.instruction_count as f64);
    gauge!("sp1_execution_syscall_count").set(stats.syscall_count as f64);
    gauge!("sp1_execution_gas").set(stats.gas as f64);
}
