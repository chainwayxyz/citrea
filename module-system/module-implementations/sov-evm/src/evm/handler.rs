use std::mem::size_of_val;
use std::sync::Arc;

use revm::handler::register::EvmHandler;
use revm::interpreter::InstructionResult;
use revm::primitives::{EVMError, ExecutionResult, ResultAndState, State, U256};
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
        let result_and_state = revm::handler::mainnet::output(context, result)?;
        let ResultAndState { result, state } = result_and_state;
        if result.is_success() {
            let diff_size = state_diff_size(&state);
            let l1_fee_rate = 1; // TODO: get it somehow
            let l1_fee = U256::from(diff_size * l1_fee_rate);
            if let Some(_out_of_funds) = decrease_caller_balance(context, l1_fee)? {
                let result = ExecutionResult::Revert {
                    gas_used: result.gas_used(),
                    output: result
                        .into_output()
                        .expect("ExecutionResult::Success always has an output"),
                };
                return Ok(ResultAndState { result, state });
            }
        }
        Ok(ResultAndState { result, state })
    }
}

/// Calculates the diff of the modified state.
fn state_diff_size(state: &State) -> usize {
    let mut diff_size = 0usize;
    for account in state.values() {
        for (k, v) in account.changed_storage_slots() {
            //
            let p = &v.previous_or_original_value;
            let c = &v.present_value;
            let slot_size = size_of_val(k) + size_of_val(p) + size_of_val(c);
            diff_size += slot_size;
        }
    }
    diff_size
}

/// Decreases the balance of the caller by the given amount.
/// Returns Ok(Some) if the caller's balance is not enough.
fn decrease_caller_balance<EXT, DB: Database>(
    context: &mut Context<EXT, DB>,
    amount: U256,
) -> Result<Option<InstructionResult>, EVMError<DB::Error>> {
    let caller = context.evm.env.tx.caller;

    let (caller_account, _) = context
        .evm
        .journaled_state
        .load_account(caller, &mut context.evm.db)?;

    let balance = &mut caller_account.info.balance;

    let Some(new_balance) = balance.checked_sub(amount) else {
        return Ok(Some(InstructionResult::OutOfFunds));
    };

    *balance = new_balance;

    Ok(None)
}
