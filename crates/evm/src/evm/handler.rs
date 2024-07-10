use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::sync::Arc;

use revm::handler::register::{EvmHandler, HandleRegisters};
#[cfg(feature = "native")]
use revm::interpreter::{CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter};
use revm::interpreter::{Gas, InstructionResult};
#[cfg(feature = "native")]
use revm::primitives::Log;
use revm::primitives::{
    spec_to_generic, Address, EVMError, Env, HandlerCfg, InvalidTransaction, ResultAndState, Spec,
    SpecId, B256, U256,
};
use revm::{Context, Database, FrameResult, InnerEvmContext, JournalEntry};
#[cfg(feature = "native")]
use revm::{EvmContext, Inspector};
use sov_modules_api::{native_debug, native_error, native_warn};
#[cfg(feature = "native")]
use tracing::instrument;

use crate::system_events::SYSTEM_SIGNER;
use crate::{BASE_FEE_VAULT, L1_FEE_VAULT};

#[derive(Copy, Clone, Default, Debug)]
pub struct TxInfo {
    pub l1_diff_size: u64,
    pub l1_fee: U256,
}

/// An external context appended to the EVM.
/// In terms of Revm this is the trait for EXT for `Evm<'a, EXT, DB>`.
pub(crate) trait CitreaExternalExt {
    /// Get current l1 fee rate.
    fn l1_fee_rate(&self) -> u128;
    /// Set tx hash for the current execution context.
    fn set_current_tx_hash(&mut self, hash: B256);
    /// Set tx info for the current tx hash.
    fn set_tx_info(&mut self, info: TxInfo);
    /// Get tx info for the given tx by its hash.
    fn get_tx_info(&self, tx_hash: B256) -> Option<TxInfo>;
}

// Blanked impl for &mut T: CitreaExternalExt
impl<T: CitreaExternalExt> CitreaExternalExt for &mut T {
    fn l1_fee_rate(&self) -> u128 {
        (**self).l1_fee_rate()
    }
    fn set_current_tx_hash(&mut self, hash: B256) {
        (**self).set_current_tx_hash(hash);
    }
    fn set_tx_info(&mut self, info: TxInfo) {
        (**self).set_tx_info(info)
    }
    fn get_tx_info(&self, tx_hash: B256) -> Option<TxInfo> {
        (**self).get_tx_info(tx_hash)
    }
}

/// This is an external context to be passed to the EVM.
/// In terms of Revm this type replaces EXT in `Evm<'a, EXT, DB>`.
#[derive(Default)]
pub(crate) struct CitreaExternal {
    l1_fee_rate: u128,
    current_tx_hash: Option<B256>,
    tx_infos: BTreeMap<B256, TxInfo>,
}

impl CitreaExternal {
    pub(crate) fn new(l1_fee_rate: u128) -> Self {
        Self {
            l1_fee_rate,
            ..Default::default()
        }
    }
}

impl CitreaExternalExt for CitreaExternal {
    fn l1_fee_rate(&self) -> u128 {
        self.l1_fee_rate
    }
    #[cfg_attr(feature = "native", instrument(level = "trace", skip(self)))]
    fn set_current_tx_hash(&mut self, hash: B256) {
        self.current_tx_hash.replace(hash);
    }
    #[cfg_attr(feature = "native", instrument(level = "trace", skip(self)))]
    fn set_tx_info(&mut self, info: TxInfo) {
        let current_tx_hash = self.current_tx_hash.take();
        if let Some(hash) = current_tx_hash {
            self.tx_infos.insert(hash, info);
        } else {
            native_error!("No hash set for the current tx in Citrea handler");
        }
    }
    fn get_tx_info(&self, tx_hash: B256) -> Option<TxInfo> {
        self.tx_infos.get(&tx_hash).copied()
    }
}

#[cfg(feature = "native")]
/// This is both a `CitreaExternal` and an `Inspector`.
pub(crate) struct TracingCitreaExternal<I, DB> {
    ext: CitreaExternal,
    pub(crate) inspector: I,
    _ph: core::marker::PhantomData<DB>,
}

#[cfg(feature = "native")]
impl<I, DB> TracingCitreaExternal<I, DB>
where
    DB: Database,
    I: Inspector<DB>,
{
    pub(crate) fn new(inspector: I, l1_fee_rate: u128) -> Self {
        Self {
            ext: CitreaExternal::new(l1_fee_rate),
            inspector,
            _ph: Default::default(),
        }
    }
}

#[cfg(feature = "native")]
// Pass all methods to self.ext
impl<I, DB> CitreaExternalExt for TracingCitreaExternal<I, DB> {
    fn l1_fee_rate(&self) -> u128 {
        self.ext.l1_fee_rate()
    }
    fn set_current_tx_hash(&mut self, hash: B256) {
        self.ext.set_current_tx_hash(hash);
    }
    fn set_tx_info(&mut self, info: TxInfo) {
        self.ext.set_tx_info(info);
    }
    fn get_tx_info(&self, tx_hash: B256) -> Option<TxInfo> {
        self.ext.get_tx_info(tx_hash)
    }
}

#[cfg(feature = "native")]
// Pass all methods to self.inspector
impl<I, DB> Inspector<DB> for TracingCitreaExternal<I, DB>
where
    DB: Database,
    I: Inspector<DB>,
{
    fn initialize_interp(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        self.inspector.initialize_interp(interp, context)
    }
    fn step(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        self.inspector.step(interp, context)
    }
    fn step_end(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        self.inspector.step_end(interp, context)
    }
    fn log(&mut self, context: &mut EvmContext<DB>, log: &Log) {
        self.inspector.log(context, log)
    }
    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        self.inspector.call(context, inputs)
    }
    fn call_end(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        self.inspector.call_end(context, inputs, outcome)
    }
    fn create(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        self.inspector.create(context, inputs)
    }
    fn create_end(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        self.inspector.create_end(context, inputs, outcome)
    }
    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        (&mut self.inspector as &mut dyn Inspector<DB>).selfdestruct(contract, target, value)
    }
}

/// Additional methods applied to the EVM environment.
trait CitreaEnv {
    /// Whether the call is made by `SYSTEM_SIGNER`.
    fn is_system_caller(&self) -> bool;
}

impl CitreaEnv for &'_ Env {
    fn is_system_caller(&self) -> bool {
        SYSTEM_SIGNER == self.tx.caller
    }
}

impl<EXT, DB: Database> CitreaEnv for &'_ mut Context<EXT, DB> {
    fn is_system_caller(&self) -> bool {
        (&*self.evm.env).is_system_caller()
    }
}

pub(crate) fn citrea_handler<'a, DB, EXT>(cfg: HandlerCfg) -> EvmHandler<'a, EXT, DB>
where
    DB: Database,
    EXT: CitreaExternalExt,
{
    let mut handler = EvmHandler::mainnet_with_spec(cfg.spec_id);
    handler.append_handler_register(HandleRegisters::Plain(citrea_handle_register));
    handler
}

pub(crate) fn citrea_handle_register<DB, EXT>(handler: &mut EvmHandler<'_, EXT, DB>)
where
    DB: Database,
    EXT: CitreaExternalExt,
{
    spec_to_generic!(handler.cfg.spec_id, {
        let validation = &mut handler.validation;
        let pre_execution = &mut handler.pre_execution;
        // let execution = &mut handler.execution;
        let post_execution = &mut handler.post_execution;
        // validation.initial_tx_gas = can be overloaded too
        // validation.env =
        validation.tx_against_state =
            Arc::new(CitreaHandler::<SPEC, EXT, DB>::validate_tx_against_state);
        // pre_execution.load_accounts =
        // pre_execution.load_accounts =
        pre_execution.deduct_caller = Arc::new(CitreaHandler::<SPEC, EXT, DB>::deduct_caller);
        // execution.last_frame_return =
        // execution.call =
        // execution.call_return =
        // execution.insert_call_outcome =
        // execution.create =
        // execution.create_return =
        // execution.insert_create_outcome =
        post_execution.reimburse_caller =
            Arc::new(CitreaHandler::<SPEC, EXT, DB>::reimburse_caller);
        post_execution.reward_beneficiary =
            Arc::new(CitreaHandler::<SPEC, EXT, DB>::reward_beneficiary);
        post_execution.output = Arc::new(CitreaHandler::<SPEC, EXT, DB>::post_execution_output);
        // post_execution.end =
    });
}

struct CitreaHandler<SPEC, EXT, DB> {
    _phantom: std::marker::PhantomData<(SPEC, EXT, DB)>,
}

impl<SPEC: Spec, EXT: CitreaExternalExt, DB: Database> CitreaHandler<SPEC, EXT, DB> {
    fn validate_tx_against_state(
        context: &mut Context<EXT, DB>,
    ) -> Result<(), EVMError<DB::Error>> {
        if context.is_system_caller() {
            // Don't verify balance but nonce only.
            let tx_caller = context.evm.env.tx.caller;
            let (caller_account, _) = context
                .evm
                .inner
                .journaled_state
                .load_account(tx_caller, &mut context.evm.inner.db)?;
            // Check that the transaction's nonce is correct
            if let Some(tx) = context.evm.inner.env.tx.nonce {
                let state = caller_account.info.nonce;
                match tx.cmp(&state) {
                    Ordering::Greater => {
                        return Err(InvalidTransaction::NonceTooHigh { tx, state })?;
                    }
                    Ordering::Less => {
                        return Err(InvalidTransaction::NonceTooLow { tx, state })?;
                    }
                    _ => {}
                }
            }
            return Ok(());
        }
        revm::handler::mainnet::validate_tx_against_state::<SPEC, EXT, DB>(context)
    }
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    fn deduct_caller(context: &mut Context<EXT, DB>) -> Result<(), EVMError<DB::Error>> {
        if context.is_system_caller() {
            // System caller doesn't spend gas.
            // bump the nonce for calls.
            // TODO check: Nonce for CREATE will be bumped in `handle_create`.
            if context.evm.env.tx.transact_to.is_call() {
                // Nonce is already checked
                let tx_caller = context.evm.env.tx.caller;
                let (caller_account, _) = context
                    .evm
                    .inner
                    .journaled_state
                    .load_account(tx_caller, &mut context.evm.inner.db)?;
                caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
            }
            return Ok(());
        }
        revm::handler::mainnet::deduct_caller::<SPEC, EXT, DB>(context)
    }
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    fn reimburse_caller(
        context: &mut Context<EXT, DB>,
        gas: &Gas,
    ) -> Result<(), EVMError<DB::Error>> {
        if context.is_system_caller() {
            // System caller doesn't spend gas.
            return Ok(());
        }
        revm::handler::mainnet::reimburse_caller::<SPEC, EXT, DB>(context, gas)
    }
    #[cfg_attr(feature = "native", instrument(level = "trace", fields(gas), skip_all))]
    fn reward_beneficiary(
        context: &mut Context<EXT, DB>,
        gas: &Gas,
    ) -> Result<(), EVMError<DB::Error>> {
        if context.is_system_caller() {
            // System caller doesn't spend gas.
            return Ok(());
        }

        let gas_used = U256::from(gas.spent() - gas.refunded() as u64);

        // Only add base fee if eip-1559 is enabled
        if SPEC::enabled(SpecId::LONDON) {
            // add base fee to base fee vault
            let base_fee_per_gas = context.evm.env.block.basefee;
            let base_fee = base_fee_per_gas * gas_used;
            change_balance(context, base_fee, true, BASE_FEE_VAULT)?;
        }

        // send priority fee to coinbase using revm mainnet behaviour
        revm::handler::mainnet::reward_beneficiary::<SPEC, EXT, DB>(context, gas)?;

        Ok(())
    }
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, fields(caller = %context.evm.env.tx.caller)))]
    fn post_execution_output(
        context: &mut Context<EXT, DB>,
        result: FrameResult,
    ) -> Result<ResultAndState, EVMError<<DB as Database>::Error>> {
        let diff_size = calc_diff_size(context).map_err(EVMError::Database)? as u64;
        let l1_fee_rate = context.external.l1_fee_rate();
        let l1_fee = U256::from(diff_size) * U256::from(l1_fee_rate);
        context.external.set_tx_info(TxInfo {
            l1_diff_size: diff_size,
            l1_fee,
        });
        if context.is_system_caller() {
            // System caller doesn't pay L1 fee.
        } else {
            if let Some(_out_of_funds) = decrease_caller_balance(context, l1_fee)? {
                return Err(EVMError::Custom(format!(
                    "Not enough funds for L1 fee: {}",
                    l1_fee
                )));
            }
            // add l1 fee to l1 fee vault
            change_balance(context, l1_fee, true, L1_FEE_VAULT)?;
        }

        revm::handler::mainnet::output(context, result)
    }
}

/// Calculates the diff of the modified state.
#[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
fn calc_diff_size<EXT, DB: Database>(
    context: &mut Context<EXT, DB>,
) -> Result<usize, <DB as Database>::Error> {
    let InnerEvmContext {
        db,
        journaled_state,
        env,
        ..
    } = &mut context.evm.inner;

    // Get the last journal entry to calculate diff.
    let journal = journaled_state.journal.last().cloned().unwrap_or(vec![]);
    let state = &journaled_state.state;

    #[derive(Default)]
    struct AccountChange<'a> {
        created: bool,
        destroyed: bool,
        nonce_changed: bool,
        code_changed: bool,
        balance_changed: bool,
        storage_changes: BTreeSet<&'a U256>,
    }

    let mut account_changes: BTreeMap<&Address, AccountChange<'_>> = BTreeMap::new();

    for entry in &journal {
        match entry {
            JournalEntry::NonceChange { address } => {
                let account = account_changes.entry(address).or_default();
                account.nonce_changed = true;
            }
            JournalEntry::BalanceTransfer { from, to, .. } => {
                let from = account_changes.entry(from).or_default();
                from.balance_changed = true;
                let to = account_changes.entry(to).or_default();
                to.balance_changed = true;
            }
            JournalEntry::StorageChange { address, key, .. } => {
                let account = account_changes.entry(address).or_default();
                account.storage_changes.insert(key);
            }
            JournalEntry::CodeChange { address } => {
                let account = account_changes.entry(address).or_default();
                account.code_changed = true;
            }
            JournalEntry::AccountCreated { address } => {
                let account = account_changes.entry(address).or_default();
                account.created = true;
                // When account is created, there is a transfer to init its balance.
                // So we need to only force the nonce change.
                account.nonce_changed = true;
            }
            JournalEntry::AccountDestroyed { address, .. } => {
                let account = account_changes.entry(address).or_default();
                if account.created {
                    // That's a temporary account.
                    // Delete it from the account changes to enable cancun support.
                    // Acc with the same address can be created again in the same tx.
                    account_changes.remove(address);
                } else {
                    account.destroyed = true;
                }
            }
            _ => {}
        }
    }
    native_debug!(
        accounts = account_changes.len(),
        "Total accounts for diff size"
    );

    let slot_size = 2 * size_of::<U256>(); // key + value;
    let mut diff_size = 0usize;

    // no matter the type of transaction or its fee rates, a tx must pay at least base fee and L1 fee
    // thus we increment the diff size by 20 (coinbase address) + 32 (coinbase balance change)
    // notice, we don't add to diff size when an address explicitly sends funds to coinbase
    if !account_changes.contains_key(&env.block.coinbase) {
        diff_size += size_of::<Address>() + size_of::<U256>();
    }

    for (addr, account) in account_changes {
        // Apply size of address of changed account
        diff_size += size_of::<Address>();

        if account.destroyed {
            let account = &state[addr];
            diff_size += slot_size * account.storage.len(); // Storage size
            diff_size += size_of::<u64>(); // Nonces are u64
            diff_size += size_of::<U256>(); // Balances are U256
            diff_size += size_of::<B256>(); // Code hashes are B256

            // Retrieve code from DB and apply its size
            if let Some(info) = db.basic(*addr)? {
                if let Some(code) = info.code {
                    diff_size += code.len();
                } else {
                    let code = db.code_by_hash(info.code_hash)?;
                    diff_size += code.len();
                }
            }
            continue;
        }

        // Apply size of changed nonce
        if account.nonce_changed {
            diff_size += size_of::<u64>(); // Nonces are u64
        }

        // Apply size of changed balances
        if account.balance_changed {
            diff_size += size_of::<U256>(); // Balances are U256
        }

        // Apply size of changed slots
        diff_size += slot_size * account.storage_changes.len();

        // Apply size of changed codes
        if account.code_changed {
            let account = &state[addr];
            diff_size += size_of::<B256>(); // Code hashes are B256
            if let Some(code) = account.info.code.as_ref() {
                diff_size += code.len()
            } else {
                native_warn!(
                    "Code must exist for account when calculating diff: {}",
                    addr,
                );
            }
        }
    }

    Ok(diff_size)
}

#[cfg_attr(feature = "native", instrument(level = "trace", skip(context)))]
fn change_balance<EXT, DB: Database>(
    context: &mut Context<EXT, DB>,
    amount: U256,
    positive: bool,
    address: Address,
) -> Result<Option<InstructionResult>, EVMError<DB::Error>> {
    let InnerEvmContext {
        journaled_state,
        db,
        ..
    } = &mut context.evm.inner;

    let (account, _) = journaled_state.load_account(address, db)?;
    account.mark_touch();

    let balance = &mut account.info.balance;
    native_debug!(%balance);

    let new_balance = if positive {
        balance.saturating_add(amount)
    } else {
        let Some(new_balance) = balance.checked_sub(amount) else {
            return Ok(Some(InstructionResult::OutOfFunds));
        };
        new_balance
    };

    *balance = new_balance;

    Ok(None)
}

/// Decreases the balance of the caller by the given amount.
/// Returns Ok(Some) if the caller's balance is not enough.
fn decrease_caller_balance<EXT, DB: Database>(
    context: &mut Context<EXT, DB>,
    amount: U256,
) -> Result<Option<InstructionResult>, EVMError<DB::Error>> {
    let address = context.evm.env.tx.caller;
    change_balance(context, amount, false, address)
}
