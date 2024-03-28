use module_template::{CallMessage, ExampleModule, ExampleModuleConfig, Response};
use sov_modules_api::default_context::{DefaultContext, ZkDefaultContext};
use sov_modules_api::{Address, Context, Event, Module, WorkingSet};
use sov_prover_storage_manager::new_orphan_storage;
use sov_state::{DefaultStorageSpec, ZkStorage};

#[test]
fn test_value_setter() {
    let tmpdir = tempfile::tempdir().unwrap();

    let storage = new_orphan_storage::<DefaultStorageSpec>(tmpdir.path()).unwrap();
    let mut working_set = WorkingSet::new(storage);

    let admin = Address::from([1; 32]);
    let sequencer = Address::from([2; 32]);

    // Test Native-Context
    {
        let config = ExampleModuleConfig {};
        let context = DefaultContext::new(admin, sequencer, 1);
        test_value_setter_helper(context, &config, &mut working_set);
    }

    let (_, witness) = working_set.checkpoint().freeze();

    // Test Zk-Context
    {
        let config = ExampleModuleConfig {};
        let zk_context = ZkDefaultContext::new(admin, sequencer, 1);
        let mut zk_working_set = WorkingSet::with_witness(ZkStorage::new(), witness);
        test_value_setter_helper(zk_context, &config, &mut zk_working_set);
    }
}

fn test_value_setter_helper<C: Context>(
    context: C,
    config: &ExampleModuleConfig,
    working_set: &mut WorkingSet<C>,
) {
    let module = ExampleModule::<C>::default();
    module.genesis(config, working_set).unwrap();

    let new_value = 99;
    let call_msg = CallMessage::SetValue(new_value);

    // Test events
    {
        module.call(call_msg, &context, working_set).unwrap();
        let event = &working_set.events()[0];
        assert_eq!(event, &Event::new("set", "value_set: 99"));
    }

    // Test query
    #[cfg(feature = "native")]
    {
        let query_response = module.query_value(working_set);
        assert_eq!(
            Response {
                value: Some(new_value)
            },
            query_response
        )
    }
}
