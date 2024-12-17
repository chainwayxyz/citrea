use sov_modules_api::{Context, Module, ModuleInfo, StateMap, WorkingSet};

#[derive(ModuleInfo)]
struct TestStruct<C: Context> {
    #[address]
    pub address: C::Address,

    test_state1: StateMap<u32, u32>,

    #[state]
    test_state2: StateMap<Vec<u8>, u64>,
}

impl<C: Context> Module for TestStruct<C> {
    type Context = C;

    type Config = ();

    type CallMessage = ();

    type Event = ();

    fn call(
        &mut self,
        _message: Self::CallMessage,
        _context: &Self::Context,
        _working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<sov_modules_api::CallResponse, sov_modules_api::SoftConfirmationModuleCallError>
    {
        todo!()
    }
}

fn main() {}
