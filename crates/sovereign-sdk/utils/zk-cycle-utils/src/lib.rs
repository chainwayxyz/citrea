use risc0_zkvm_platform::syscall::SyscallName;

pub fn get_syscall_name() -> SyscallName {
    let name = c"cycle_metrics".as_ptr();
    unsafe { SyscallName::from_bytes_with_nul(name as _) }
}

#[cfg(feature = "native")]
pub fn cycle_count_callback(input: risc0_zkvm::Bytes) -> risc0_zkvm::Result<risc0_zkvm::Bytes> {
    if input.len() == std::mem::size_of::<usize>() {
        let mut array = [0u8; std::mem::size_of::<usize>()];
        array.copy_from_slice(&input);
        println!("== syscall ==> {}", usize::from_le_bytes(array));
    } else {
        println!("NONE");
    }
    Ok(risc0_zkvm::Bytes::new())
}

pub fn get_syscall_name_cycles() -> SyscallName {
    let name = c"cycle_count".as_ptr();
    unsafe { SyscallName::from_bytes_with_nul(name as _) }
}

pub fn print_cycle_count() {
    let metrics_syscall_name = get_syscall_name_cycles();
    let serialized = risc0_zkvm::guest::env::cycle_count().to_le_bytes();
    risc0_zkvm::guest::env::send_recv_slice::<u8, u8>(metrics_syscall_name, &serialized);
}
