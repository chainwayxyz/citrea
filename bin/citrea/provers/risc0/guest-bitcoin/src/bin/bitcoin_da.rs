#![no_main]
use bitcoin_da::spec::BitcoinSpec;
use bitcoin_da::verifier::BitcoinVerifier;
use borsh::BorshDeserialize;
use citrea_stf::runtime::Runtime;
use risc0_zkvm::guest::env;
use sov_modules_api::default_context::ZkDefaultContext;
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::StateTransitionData;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::da::DaVerifier;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    // !! VEC ALLOC IMPL !!

    // // read len(u64) in LE
    // let mut len_buf = [0u8; 8];
    // env::read_slice(&mut len_buf);
    // let len = u64::from_le_bytes(len_buf);
    // // read buf
    // let mut buf: Vec<u32> = vec![0; len as usize];
    // env::read_slice(&mut buf);
    // let slice: &[u8] = bytemuck::cast_slice(&buf);
    // // deserialize
    // let _input: StateTransitionData<
    //     <StfBlueprint<ZkDefaultContext, BitcoinSpec, Risc0Guest, Runtime<ZkDefaultContext, BitcoinSpec>> as StateTransitionFunction<Risc0Guest, BitcoinSpec>>::StateRoot,
    //     <StfBlueprint<ZkDefaultContext, BitcoinSpec, Risc0Guest, Runtime<ZkDefaultContext, BitcoinSpec>> as StateTransitionFunction<Risc0Guest, BitcoinSpec>>::Witness,
    //     <BitcoinVerifier as DaVerifier>::Spec,
    // > = BorshDeserialize::deserialize(&mut &*slice).expect("Failed to deserialize input from host");

    // !! READER IMPL !!

    let mut reader = env::stdin();
    let _input: StateTransitionData<
        <StfBlueprint<ZkDefaultContext, BitcoinSpec, Risc0Guest, Runtime<ZkDefaultContext, BitcoinSpec>> as StateTransitionFunction<Risc0Guest, BitcoinSpec>>::StateRoot,
        <StfBlueprint<ZkDefaultContext, BitcoinSpec, Risc0Guest, Runtime<ZkDefaultContext, BitcoinSpec>> as StateTransitionFunction<Risc0Guest, BitcoinSpec>>::Witness,
        <BitcoinVerifier as DaVerifier>::Spec,
    > = BorshDeserialize::deserialize_reader(&mut reader).expect("Failed to deserialize input from host");
}
