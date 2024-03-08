use std::collections::HashSet;
use std::mem::{size_of, size_of_val};
use std::sync::Arc;

use revm::handler::register::EvmHandler;
use revm::interpreter::InstructionResult;
use revm::primitives::{Address, EVMError, ExecutionResult, ResultAndState, State, U256};
use revm::{Context, Database, FrameResult, JournalEntry};

pub(crate) trait CitreaExternal {
    fn l1_fee_rate(&self) -> u64;
}
pub(crate) struct CitreaExternalContext {
    l1_fee_rate: u64,
}

impl CitreaExternalContext {
    pub(crate) fn new(l1_fee_rate: u64) -> Self {
        Self { l1_fee_rate }
    }
}

impl CitreaExternal for CitreaExternalContext {
    fn l1_fee_rate(&self) -> u64 {
        self.l1_fee_rate
    }
}

pub(crate) fn citrea_handle_register<DB, EXT>(handler: &mut EvmHandler<'_, EXT, DB>)
where
    DB: Database,
    EXT: CitreaExternal,
{
    let post_execution = &mut handler.post_execution;
    post_execution.output = Arc::new(CitreaHandler::<EXT, DB>::post_execution_output);
}

struct CitreaHandler<EXT, DB> {
    _phantom: std::marker::PhantomData<(EXT, DB)>,
}

impl<EXT: CitreaExternal, DB: Database> CitreaHandler<EXT, DB> {
    fn post_execution_output(
        context: &mut Context<EXT, DB>,
        result: FrameResult,
    ) -> Result<ResultAndState, EVMError<<DB as Database>::Error>> {
        // We have to copy the journal entry because
        // it will be modified by the mainnet::output function.
        let journal = context
            .evm
            .journaled_state
            .journal
            .last()
            .cloned()
            .unwrap_or(vec![]);

        let result_and_state = revm::handler::mainnet::output(context, result)?;
        let ResultAndState { result, state } = result_and_state;
        if result.is_success() {
            let diff_size = U256::from(state_diff_size(&state, journal));
            let l1_fee_rate = U256::from(context.external.l1_fee_rate());
            let l1_fee = diff_size * l1_fee_rate;
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
fn state_diff_size(state: &State, journal: Vec<JournalEntry>) -> usize {
    let nonce_changes: HashSet<&Address> = journal
        .iter()
        .filter_map(|entry| match entry {
            JournalEntry::NonceChange { address } => Some(address),
            _ => None,
        })
        .collect();

    let balance_changes: HashSet<&Address> = journal
        .iter()
        .filter_map(|entry| match entry {
            JournalEntry::BalanceTransfer { from, to, .. } => Some([from, to]),
            _ => None,
        })
        .flatten()
        .collect();

    let storage_changes: HashSet<&Address> = journal
        .iter()
        .filter_map(|entry| match entry {
            JournalEntry::StorageChange { address, .. } => Some(address),
            _ => None,
        })
        .collect();

    let mut all_changed_addresses = HashSet::<&Address>::new();
    all_changed_addresses.extend(&nonce_changes);
    all_changed_addresses.extend(&balance_changes);
    all_changed_addresses.extend(&storage_changes);

    let mut diff_size = 0usize;

    // Apply size of changed addresses
    for _addr in all_changed_addresses {
        diff_size += size_of::<Address>();
    }

    // Apply size of changed nonces
    for _addr in nonce_changes {
        diff_size += size_of::<u64>(); // Nonces are u64
    }

    // Apply size of changed balances
    for _addr in balance_changes {
        diff_size += size_of::<U256>(); // Balances are U256
    }

    // Apply size of changed slots
    for account in state.values() {
        for (k, v) in account.changed_storage_slots() {
            // TODO diff calc https://github.com/chainwayxyz/secret-sovereign-sdk/issues/116
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
