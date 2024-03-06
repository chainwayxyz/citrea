use std::sync::Arc;

use revm::handler::register::EvmHandler;
use revm::primitives::{EVMError, ResultAndState};
use revm::{Context, Database, FrameResult};

pub(crate) fn citrea_handle_register<EXT, DB>(handler: &mut EvmHandler<'_, EXT, DB>)
where
    DB: Database,
{
    let post_execution = &mut handler.post_execution;
    post_execution.output = Arc::new(CitreaHandler::<EXT, DB>::post_execution_output);
}

struct CitreaHandler<EXT, DB> {
    _phantom: std::marker::PhantomData<(EXT, DB)>,
}

impl<EXT, DB: Database> CitreaHandler<EXT, DB> {
    fn post_execution_output(
        context: &mut Context<EXT, DB>,
        result: FrameResult,
    ) -> Result<ResultAndState, EVMError<<DB as Database>::Error>> {
        revm::handler::mainnet::output(context, result)
    }
}
