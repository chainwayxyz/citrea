#![no_main]
use citrea_light_client_prover::circuit::run_circuit;
use citrea_light_client_prover::input::LightClientCircuitInput;
#[cfg(feature = "bench")]
use risc0_zkvm::guest::env;
use sov_mock_da::{MockDaSpec, MockDaVerifier};
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::zk::ZkvmGuest;

#[cfg(feature = "bench")]
fn report_bench_metrics(start_cycles: u64, end_cycles: u64) {
    let cycles_per_block = end_cycles - start_cycles;
    let tuple = ("Cycles per block".to_string(), cycles_per_block);
    let mut serialized = Vec::new();
    serialized.extend(tuple.0.as_bytes());
    serialized.push(0);
    let size_bytes = tuple.1.to_ne_bytes();
    serialized.extend(&size_bytes);

    // calculate the syscall name.
    let name = c"cycle_metrics";
    let metrics_syscall_name = risc0_zkvm_platform::syscall::SyscallName::from_c_str(name).unwrap();

    risc0_zkvm::guest::env::send_recv_slice::<u8, u8>(metrics_syscall_name, &serialized);
}

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let guest = Risc0Guest::new();
    #[cfg(feature = "bench")]
    let start_cycles = env::cycle_count();

    let input: LightClientCircuitInput<MockDaSpec> = guest.read_from_host();

    let da_verifier = MockDaVerifier {};

    let output = run_circuit::<MockDaVerifier>(input, da_verifier).unwrap();

    guest.commit(&output);

    #[cfg(feature = "bench")]
    {
        let end_cycles = env::cycle_count();
        report_bench_metrics(start_cycles, end_cycles);
    }
}
