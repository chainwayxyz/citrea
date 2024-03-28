use sov_modules_api::{Context, ModuleInfo, StateMap, StateValue, WorkingSet};

pub mod module_a {
    use sov_modules_api::{Module, StateMapAccessor, StateValueAccessor};

    use super::*;

    #[derive(ModuleInfo)]
    pub(crate) struct ModuleA<C: Context> {
        #[address]
        pub address_module_a: C::Address,

        #[state]
        pub(crate) state_1_a: StateMap<String, String>,

        #[state]
        pub(crate) state_2_a: StateValue<String>,
    }

    impl<C: Context> Module for ModuleA<C> {
        type Context = C;

        type Config = ();

        type CallMessage = ();

        type Event = ();

        fn call(
            &self,
            _message: Self::CallMessage,
            _context: &Self::Context,
            _working_set: &mut WorkingSet<Self::Context>,
        ) -> Result<sov_modules_api::CallResponse, sov_modules_api::Error> {
            todo!()
        }
    }

    impl<C: Context> ModuleA<C> {
        pub fn update(&mut self, key: &str, value: &str, working_set: &mut WorkingSet<C>) {
            working_set.add_event("module A", "update");
            self.state_1_a
                .set(&key.to_owned(), &value.to_owned(), working_set);
            self.state_2_a.set(&value.to_owned(), working_set)
        }
    }
}

pub mod module_b {
    use sov_modules_api::{Module, StateMapAccessor};

    use super::*;

    #[derive(ModuleInfo)]
    pub(crate) struct ModuleB<C: Context> {
        #[address]
        pub address_module_b: C::Address,

        #[state]
        state_1_b: StateMap<String, String>,

        #[module]
        pub(crate) mod_1_a: module_a::ModuleA<C>,
    }

    impl<C: Context> Module for ModuleB<C> {
        type Context = C;

        type Config = ();

        type CallMessage = ();

        type Event = ();

        fn call(
            &self,
            _message: Self::CallMessage,
            _context: &Self::Context,
            _working_set: &mut WorkingSet<Self::Context>,
        ) -> Result<sov_modules_api::CallResponse, sov_modules_api::Error> {
            todo!()
        }
    }

    impl<C: Context> ModuleB<C> {
        pub fn update(&mut self, key: &str, value: &str, working_set: &mut WorkingSet<C>) {
            working_set.add_event("module B", "update");
            self.state_1_b
                .set(&key.to_owned(), &value.to_owned(), working_set);
            self.mod_1_a.update("key_from_b", value, working_set);
        }
    }
}

pub(crate) mod module_c {
    use sov_modules_api::Module;

    use super::*;

    #[derive(ModuleInfo)]
    pub(crate) struct ModuleC<C: Context> {
        #[address]
        pub address: C::Address,

        #[module]
        pub(crate) mod_1_a: module_a::ModuleA<C>,

        #[module]
        mod_1_b: module_b::ModuleB<C>,
    }

    impl<C: Context> Module for ModuleC<C> {
        type Context = C;

        type Config = ();

        type CallMessage = ();

        type Event = ();

        fn call(
            &self,
            _message: Self::CallMessage,
            _context: &Self::Context,
            _working_set: &mut WorkingSet<Self::Context>,
        ) -> Result<sov_modules_api::CallResponse, sov_modules_api::Error> {
            todo!()
        }
    }

    impl<C: Context> ModuleC<C> {
        pub fn execute(&mut self, key: &str, value: &str, working_set: &mut WorkingSet<C>) {
            working_set.add_event("module C", "execute");
            self.mod_1_a.update(key, value, working_set);
            self.mod_1_b.update(key, value, working_set);
            self.mod_1_a.update(key, value, working_set);
        }
    }
}
