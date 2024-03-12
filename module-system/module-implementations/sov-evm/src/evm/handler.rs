use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::sync::Arc;

use revm::handler::register::EvmHandler;
use revm::interpreter::InstructionResult;
use revm::primitives::{Address, EVMError, ExecutionResult, HaltReason, ResultAndState, U256};
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
        if !result.interpreter_result().is_error() {
            // Get the last journal entry to calculate diff.
            let journal = context
                .evm
                .journaled_state
                .journal
                .last()
                .cloned()
                .unwrap_or(vec![]);
            let diff_size = U256::from(journal_diff_size(journal));
            let l1_fee_rate = U256::from(context.external.l1_fee_rate());
            let l1_fee = diff_size * l1_fee_rate;
            if let Some(_out_of_funds) = decrease_caller_balance(context, l1_fee)? {
                let gas_refunded = result.gas().refunded() as u64;
                let final_gas_used = result.gas().spend() - gas_refunded;
                // reset journal and return present state.
                let (state, _) = context.evm.journaled_state.finalize();

                context.evm.error = Err(EVMError::Custom("Not enought funds for L1 fee".into()));

                let result = ExecutionResult::Halt {
                    reason: HaltReason::OutOfFunds,
                    gas_used: final_gas_used,
                };
                return Ok(ResultAndState { result, state });
            }
        }

        revm::handler::mainnet::output(context, result)
    }
}

/// Calculates the diff of the modified state.
fn journal_diff_size(journal: Vec<JournalEntry>) -> usize {
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

    let storage_changes: HashMap<&Address, _> = journal
        .iter()
        .filter_map(|entry| match entry {
            JournalEntry::StorageChange { address, key, .. } => Some((address, key)),
            _ => None,
        })
        .collect();

    let mut all_changed_addresses = HashSet::<&Address>::new();
    all_changed_addresses.extend(&nonce_changes);
    all_changed_addresses.extend(&balance_changes);
    all_changed_addresses.extend(storage_changes.keys());

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
    for _slot in storage_changes.values() {
        // TODO diff calc https://github.com/chainwayxyz/secret-sovereign-sdk/issues/116
        let slot_size = 3 * size_of::<U256>(); // key, prev, present;
        diff_size += slot_size;
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
        *balance = U256::from(0); // If the balance is not enough, set it to 0.
        return Ok(Some(InstructionResult::OutOfFunds));
    };

    *balance = new_balance;

    Ok(None)
}
