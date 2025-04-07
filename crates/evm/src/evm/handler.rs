use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use once_cell::race::OnceBox;
use revm::context::result::{
    EVMError, FromStringError, HaltReason, InvalidTransaction, ResultAndState,
};
use revm::context::{
    Block, BlockEnv, Cfg, CfgEnv, ContextSetters, ContextTr, Evm, EvmData, JournalTr, Transaction,
    TxEnv,
};
use revm::handler::instructions::{EthInstructions, InstructionProvider};
// use revm::handler::register::{EvmHandler, HandleRegisterBox, HandleRegisters};
use revm::handler::{
    EthFrame, EthPrecompiles, EvmTr, EvmTrError, Frame, FrameResult, Handler, MainnetHandler,
    PrecompileProvider,
};
#[cfg(feature = "native")]
use revm::inspector::{InspectorEvmTr, InspectorFrame, InspectorHandler};
use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::{
    FrameInput, InputsImpl, InstructionResult, Interpreter, InterpreterResult, InterpreterTypes,
};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{Address, B256, KECCAK_EMPTY, U256};
use revm::{Context, Database, ExecuteEvm, Journal, JournalEntry};
#[cfg(feature = "native")]
use revm::{InspectEvm, Inspector};
use revm_precompile::secp256r1::P256VERIFY;
use revm_precompile::{bls12_381, Precompiles};
use sov_modules_api::{native_debug, native_error};
#[cfg(feature = "native")]
use tracing::instrument;

use crate::precompiles::schnorr::SCHNORRVERIFY;
use crate::system_events::SYSTEM_SIGNER;
use crate::{BASE_FEE_VAULT, L1_FEE_VAULT};

/// 4 bytes of prefix ("E/i/") + 20 bytes of address = 24 bytes
const ACCOUNT_IDX_KEY_SIZE: usize = 24;

/// Account index is 64 bit integer
const ACCOUNT_IDX_SIZE: usize = 8;

/// Eoa size is reduced because code_hash for eoas are None on state diff, converted to empty Keccak internally for evm operations
const DB_ACCOUNT_SIZE_EOA: usize = 41;
const DB_ACCOUNT_SIZE_CONTRACT: usize = 73;

/// 4 bytes of prefix ("E/a/") + 8 bytes of account id = 12 bytes
const DB_ACCOUNT_KEY_SIZE: usize = 12;

/// 4 bytes of prefix ("E/s/") + 32 bytes of storage hash = 36 bytes
const STORAGE_KEY_SIZE: usize = 36;

/// Storage value is 32 bytes
const STORAGE_VALUE_SIZE: usize = 32;

/// We write data to da besides account and code data like block hashes, pending transactions and some other state variables that are in modules: evm, l2_block_rule_enforcer and sov_accounts
/// The L1 fee overhead is to compensate for the data written to da that is not accounted for in the diff size
/// It is calculated by measuring the state diff we write to da in a single batch every 10 minutes which is about 300 l2 blocks
/// The full calculation can be found here: https://github.com/chainwayxyz/citrea/blob/erce/l1-fee-overhead-calculations/l1_fee_overhead.md
pub const L1_FEE_OVERHEAD: usize = 2;

/// The brotli average compression ratio (compressed size / uncompressed size) was calculated by measuring the size of state diffs of batches before and after brotli compression.
/// calculated diff size * BROTLI_COMPRESSION_PERCENTAGE/100 gives the estimated size of the state diff that is written to the da.
pub const BROTLI_COMPRESSION_PERCENTAGE: usize = 48;

/// We want to charge the user for the amount of data written as fairly as possible, the problem is at the time of when we write batch proof to the da we cannot know the exact state diff
/// So we calculate the state diff created by a single transaction and use that to charge user
/// However at the time of the batch proof some state diffs will be merged and some users will be overcharged.
/// To tackle this we calculated statistics on the ratio between the merged state diff and unique changes vs total changes
/*
Let's consider a batch of 1 block with the following transactions:

    Block 1:
        Transaction 1: Account A transfers balance to Account C
        Transaction 2: Account B transfers balance to Account C

    In this account A and B pays for the account info diff of C, but at the end of the batch the diffs are merged and there is one state diff for C
    So A and B should share that cost
    So the ratio would be something like this in this simple scenario:
    3 unique account info slots (A,B,C) / 4 total changes (A,B,C,C) = 3/4 = 0.75
    If every user pays 0.75 of the account info state diff they created, the total state diff will be covered
*/
const STORAGE_DISCOUNTED_PERCENTAGE: usize = 66;
const ACCOUNT_DISCOUNTED_PERCENTAGE: usize = 32;

#[derive(Copy, Clone, Default, Debug)]
pub struct TxInfo {
    pub l1_diff_size: u64,
    #[allow(unused)]
    pub l1_fee: U256,
}

/// An external context appended to the EVM.
/// In terms of Revm this is the trait for CHAIN for `ContextTr<Chain = CHAIN>`.
pub(crate) trait CitreaChainExt {
    /// Get current l1 fee rate.
    fn l1_fee_rate(&self) -> u128;
    /// Set tx hash for the current execution context.
    fn set_current_tx_hash(&mut self, hash: &B256);
    /// Set tx info for the current tx hash.
    fn set_tx_info(&mut self, info: TxInfo);
    /// Get tx info for the given tx by its hash.
    fn get_tx_info(&self, tx_hash: &B256) -> Option<TxInfo>;
}

// Blanked impl for &mut T: CitreaExternalExt
impl<T: CitreaChainExt> CitreaChainExt for &mut T {
    fn l1_fee_rate(&self) -> u128 {
        (**self).l1_fee_rate()
    }
    fn set_current_tx_hash(&mut self, hash: &B256) {
        (**self).set_current_tx_hash(hash);
    }
    fn set_tx_info(&mut self, info: TxInfo) {
        (**self).set_tx_info(info)
    }
    fn get_tx_info(&self, tx_hash: &B256) -> Option<TxInfo> {
        (**self).get_tx_info(tx_hash)
    }
}

/// This is an external context to be passed to the EVM.
/// In terms of Revm this type replaces EXT in `Evm<'a, EXT, DB>`.
#[derive(Default)]
pub(crate) struct CitreaChain {
    l1_fee_rate: u128,
    current_tx_hash: Option<B256>,
    tx_infos: BTreeMap<B256, TxInfo>,
}

impl CitreaChain {
    pub(crate) fn new(l1_fee_rate: u128) -> Self {
        Self {
            l1_fee_rate,
            ..Default::default()
        }
    }
}

impl CitreaChainExt for CitreaChain {
    fn l1_fee_rate(&self) -> u128 {
        self.l1_fee_rate
    }
    #[cfg_attr(feature = "native", instrument(level = "trace", skip(self)))]
    fn set_current_tx_hash(&mut self, hash: &B256) {
        self.current_tx_hash.replace(hash.to_owned());
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
    fn get_tx_info(&self, tx_hash: &B256) -> Option<TxInfo> {
        self.tx_infos.get(tx_hash).copied()
    }
}

/// Additional methods applied to the EVM environment.
trait CitreaCallExt {
    /// Whether the call is made by `SYSTEM_SIGNER`.
    fn is_system_caller(&self) -> bool;
}

impl<EVM: EvmTr> CitreaCallExt for EVM {
    fn is_system_caller(&self) -> bool {
        SYSTEM_SIGNER == self.ctx_ref().tx().caller()
    }
}

pub struct CitreaEvm<CTX, INSP>(
    pub Evm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, CitreaPrecompiles>,
);

impl<CTX: CitreaContextTr, INSP> CitreaEvm<CTX, INSP> {
    pub fn new(ctx: CTX, inspector: INSP) -> Self {
        Self(Evm {
            data: EvmData { ctx, inspector },
            instruction: EthInstructions::new_mainnet(),
            precompiles: CitreaPrecompiles::default(),
        })
    }
}

impl<CTX, INSP> EvmTr for CitreaEvm<CTX, INSP>
where
    CTX: CitreaContextTr,
{
    type Context = CTX;
    type Instructions = EthInstructions<EthInterpreter, CTX>;
    type Precompiles = CitreaPrecompiles;

    fn run_interpreter(
        &mut self,
        interpreter: &mut Interpreter<
            <Self::Instructions as InstructionProvider>::InterpreterTypes,
        >,
    ) -> <<Self::Instructions as InstructionProvider>::InterpreterTypes as InterpreterTypes>::Output
    {
        let context = &mut self.0.data.ctx;
        let instructions = &mut self.0.instruction;
        interpreter.run_plain(instructions.instruction_table(), context)
    }

    fn ctx(&mut self) -> &mut Self::Context {
        &mut self.0.data.ctx
    }

    fn ctx_ref(&self) -> &Self::Context {
        &self.0.data.ctx
    }

    fn ctx_instructions(&mut self) -> (&mut Self::Context, &mut Self::Instructions) {
        (&mut self.0.data.ctx, &mut self.0.instruction)
    }

    fn ctx_precompiles(&mut self) -> (&mut Self::Context, &mut Self::Precompiles) {
        (&mut self.0.data.ctx, &mut self.0.precompiles)
    }
}

#[cfg(feature = "native")]
impl<CTX, INSP> InspectorEvmTr for CitreaEvm<CTX, INSP>
where
    CTX: CitreaContextTr + ContextSetters,
    INSP: Inspector<CTX>,
{
    type Inspector = INSP;

    fn inspector(&mut self) -> &mut Self::Inspector {
        &mut self.0.data.inspector
    }

    fn ctx_inspector(&mut self) -> (&mut Self::Context, &mut Self::Inspector) {
        (&mut self.0.data.ctx, &mut self.0.data.inspector)
    }

    fn run_inspect_interpreter(
        &mut self,
        interpreter: &mut Interpreter<
            <Self::Instructions as InstructionProvider>::InterpreterTypes,
        >,
    ) -> <<Self::Instructions as InstructionProvider>::InterpreterTypes as InterpreterTypes>::Output
    {
        self.0.run_inspect_interpreter(interpreter)
    }
}

/// Type alias for the error type of the CitreaEvm.
type CitreaError<CTX> =
    EVMError<<<CTX as ContextTr>::Db as Database>::Error /*CitreaTransactionError*/>;

impl<CTX, INSP> ExecuteEvm for CitreaEvm<CTX, INSP>
where
    CTX: CitreaContextTr + ContextSetters,
{
    type Output = Result<ResultAndState<HaltReason /*TODO CitreaHaltReason */>, CitreaError<CTX>>;

    type Tx = <CTX as ContextTr>::Tx;

    type Block = <CTX as ContextTr>::Block;

    fn set_tx(&mut self, tx: Self::Tx) {
        self.0.data.ctx.set_tx(tx);
    }

    fn set_block(&mut self, block: Self::Block) {
        self.0.data.ctx.set_block(block);
    }

    fn replay(&mut self) -> Self::Output {
        let mut h = CitreaHandler::<_, _, EthFrame<_, _, _>>::new();
        h.run(self)
    }
}

#[cfg(feature = "native")]
impl<CTX, INSP> InspectEvm for CitreaEvm<CTX, INSP>
where
    CTX: CitreaContextTr + ContextSetters,
    INSP: Inspector<CTX>,
{
    type Inspector = INSP;

    fn set_inspector(&mut self, inspector: Self::Inspector) {
        self.0.data.inspector = inspector;
    }

    fn inspect_replay(&mut self) -> Self::Output {
        let mut h = CitreaHandler::<_, _, EthFrame<_, _, _>>::new();
        h.inspect_run(self)
    }
}

/// Type alias for the default context type of the CitreaEvm.
pub type CitreaContext<'a, DB> =
    Context<BlockEnv, TxEnv, CfgEnv, DB, Journal<DB>, &'a mut CitreaChain>;

// Type alias for Citrea context
pub trait CitreaContextTr:
    ContextTr<
    Journal = Journal<<Self as ContextTr>::Db>,
    Tx: Transaction,
    Cfg: Cfg,
    Chain: CitreaChainExt,
>
{
}

impl<T, DB: Database> CitreaContextTr for T where
    T: ContextTr<Db = DB, Journal = Journal<DB>, Chain: CitreaChainExt>
{
}

/// Trait that allows for citrea CitreaEvm to be built.
pub trait CitreaBuilder {
    /// Type of the context.
    type Context;

    /// Build citrea.
    fn build_citrea(self) -> CitreaEvm<Self::Context, ()>;

    /// Build citrea with an inspector.
    fn build_citrea_with_inspector<INSP>(self, inspector: INSP) -> CitreaEvm<Self::Context, INSP>;
}

impl<BLOCK, TX, CFG, DB, CHAIN> CitreaBuilder for Context<BLOCK, TX, CFG, DB, Journal<DB>, CHAIN>
where
    BLOCK: Block,
    TX: Transaction,
    CFG: Cfg,
    DB: Database,
    CHAIN: CitreaChainExt,
{
    type Context = Self;

    fn build_citrea(self) -> CitreaEvm<Self::Context, ()> {
        CitreaEvm::new(self, ())
    }

    fn build_citrea_with_inspector<INSP>(self, inspector: INSP) -> CitreaEvm<Self::Context, INSP> {
        CitreaEvm::new(self, inspector)
    }
}

// Citrea precompile provider
#[derive(Debug, Clone)]
pub struct CitreaPrecompiles {
    /// Inner precompile provider is same as Ethereums.
    inner: EthPrecompiles,
}

/// Returns precompiles.
pub fn citrea_precompiles() -> &'static Precompiles {
    static INSTANCE: OnceBox<Precompiles> = OnceBox::new();
    INSTANCE.get_or_init(|| {
        // Berlin because POINT_EVALUATION precompile(0x0A) is enabled in Cancun
        // then we add prague precompiles
        // and then we add the rest of the precompiles
        let mut precompiles = Precompiles::berlin().clone();

        // Add prague precompiles
        // Effectively skipping kzg precompiles in Cancun
        precompiles.extend(bls12_381::precompiles());

        precompiles.extend([P256VERIFY, SCHNORRVERIFY]);

        Box::new(precompiles)
    })
}

impl CitreaPrecompiles {
    /// Create a new precompile provider with the given Spec.
    #[inline]
    pub fn new_with_spec(spec: SpecId) -> Self {
        let precompiles = citrea_precompiles();

        Self {
            inner: EthPrecompiles { precompiles, spec },
        }
    }
}

impl<CTX> PrecompileProvider<CTX> for CitreaPrecompiles
where
    CTX: ContextTr,
{
    type Output = InterpreterResult;

    #[inline]
    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        let spec = spec.into();
        // generate new precompiles only on new spec
        if spec == self.inner.spec {
            return false;
        }
        *self = Self::new_with_spec(spec);
        true
    }

    #[inline]
    fn run(
        &mut self,
        context: &mut CTX,
        address: &Address,
        inputs: &InputsImpl,
        is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<Self::Output>, String> {
        self.inner
            .run(context, address, inputs, is_static, gas_limit)
    }

    #[inline]
    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        self.inner.warm_addresses()
    }

    #[inline]
    fn contains(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }
}

impl Default for CitreaPrecompiles {
    fn default() -> Self {
        Self::new_with_spec(SpecId::PRAGUE)
    }
}

pub(crate) struct CitreaHandler<EVM, ERROR, FRAME> {
    pub mainnet: MainnetHandler<EVM, ERROR, FRAME>,
}

impl<EVM, ERROR, FRAME> CitreaHandler<EVM, ERROR, FRAME> {
    fn new() -> Self {
        Self {
            mainnet: Default::default(),
        }
    }
}

impl<EVM, ERROR, FRAME> Handler for CitreaHandler<EVM, ERROR, FRAME>
where
    EVM: EvmTr<Context: CitreaContextTr>,
    ERROR: EvmTrError<EVM> /*+ From<CitreaTransactionError>*/ + FromStringError, /*+ IsTxError*/
    FRAME: Frame<Evm = EVM, Error = ERROR, FrameResult = FrameResult, FrameInit = FrameInput>,
{
    type Evm = EVM;
    type Error = ERROR;
    type Frame = FRAME;
    type HaltReason = HaltReason; // TODO: CitreaHaltReason ??

    fn validate_tx_against_state(&self, evm: &mut Self::Evm) -> Result<(), Self::Error> {
        if evm.is_system_caller() {
            // Don't verify balance but nonce only.
            let context = evm.ctx();
            let tx_caller = context.tx().caller();
            let tx = context.tx().nonce();
            let caller_account = context.journal().load_account(tx_caller)?;
            // Check that the transaction's nonce is correct
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
            return Ok(());
        }
        self.mainnet.validate_tx_against_state(evm)
    }

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    fn deduct_caller(&self, evm: &mut Self::Evm) -> Result<(), Self::Error> {
        if evm.is_system_caller() {
            // System caller doesn't spend gas.

            let context = evm.ctx();

            let is_call = context.tx().kind().is_call();
            let caller = context.tx().caller();

            // Load caller's account.
            let mut caller_account = context.journal().load_account(caller)?;

            // Bump the nonce for calls. Nonce for CREATE will be bumped in `handle_create`.
            if is_call {
                // Nonce is already checked
                caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
            }

            // Touch account so we know it is changed.
            caller_account.mark_touch();

            return Ok(());
        }
        self.mainnet.deduct_caller(evm)
    }

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    fn reimburse_caller(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut <Self::Frame as Frame>::FrameResult,
    ) -> Result<(), Self::Error> {
        if evm.is_system_caller() {
            // System caller doesn't spend gas.
            return Ok(());
        }
        self.mainnet.reimburse_caller(evm, exec_result)
    }

    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", fields(exec_result), skip_all)
    )]
    fn reward_beneficiary(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut <Self::Frame as Frame>::FrameResult,
    ) -> Result<(), Self::Error> {
        if evm.is_system_caller() {
            // System caller doesn't spend gas.
            return Ok(());
        }

        let gas = exec_result.gas();
        let gas_used = U256::from(gas.spent() - gas.refunded() as u64);

        let context = evm.ctx();
        // Only add base fee if eip-1559 is enabled
        if context.cfg().spec().into().is_enabled_in(SpecId::LONDON) {
            // add base fee to base fee vault
            let base_fee_per_gas = context.block().basefee();
            let base_fee_per_gas = U256::from(base_fee_per_gas);
            let base_fee = base_fee_per_gas * gas_used;
            change_balance(context, base_fee, true, BASE_FEE_VAULT)?;
        }

        self.mainnet.reward_beneficiary(evm, exec_result)
    }

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, fields(caller = %evm.ctx_ref().tx().caller())))]
    fn output(
        &self,
        evm: &mut Self::Evm,
        result: <Self::Frame as Frame>::FrameResult,
    ) -> Result<revm::context::result::ResultAndState<Self::HaltReason>, Self::Error> {
        let uncompressed_size = calc_diff_size(evm.ctx());

        // Estimate the size of the state diff after the brotli compression
        let diff_size = (uncompressed_size * BROTLI_COMPRESSION_PERCENTAGE / 100) as u64;

        let l1_fee_rate = evm.ctx().chain().l1_fee_rate();
        let l1_fee =
            U256::from(l1_fee_rate) * (U256::from(diff_size) + U256::from(L1_FEE_OVERHEAD));
        evm.ctx().chain().set_tx_info(TxInfo {
            l1_diff_size: diff_size,
            l1_fee,
        });
        // System caller doesn't pay L1 fee.
        if !evm.is_system_caller() {
            if let Some(_out_of_funds) = decrease_caller_balance(evm.ctx(), l1_fee)? {
                return Err(ERROR::from_string(format!(
                    "Not enough funds for L1 fee: {}",
                    l1_fee
                )));
            }
            // add l1 fee to l1 fee vault
            change_balance(evm.ctx(), l1_fee, true, L1_FEE_VAULT)?;
        }

        self.mainnet.output(evm, result)
    }
}

#[cfg(feature = "native")]
impl<EVM, ERROR, FRAME> InspectorHandler for CitreaHandler<EVM, ERROR, FRAME>
where
    EVM: InspectorEvmTr<
        Context: CitreaContextTr,
        Inspector: Inspector<<<Self as Handler>::Evm as EvmTr>::Context, EthInterpreter>,
    >,
    ERROR: EvmTrError<EVM> + FromStringError,
    // TODO `FrameResult` should be a generic trait.
    // TODO `FrameInit` should be a generic.
    FRAME: InspectorFrame<
        Evm = EVM,
        Error = ERROR,
        FrameResult = FrameResult,
        FrameInit = FrameInput,
        IT = EthInterpreter,
    >,
{
    type IT = EthInterpreter;
}

/// Calculates the diff of the modified state.
#[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
fn calc_diff_size<CTX>(context: &mut CTX) -> usize
where
    CTX: CitreaContextTr,
{
    let tx_caller = context.tx().caller();
    let journaled_state = context.journal_ref();

    // For each call there is a journal entry.
    // We need to iterate over all journal entries to get the size of the diff.
    let journal = journaled_state.journal.iter().flatten();
    let state = &journaled_state.state;

    #[derive(Default)]
    struct AccountChange<'a> {
        created: bool,
        destroyed: bool,
        storage_changes: BTreeSet<&'a U256>,
        code_changed: bool,         // implies code and code hash changed
        account_info_changed: bool, // implies balance or nonce changed
    }

    let mut account_changes: BTreeMap<&Address, AccountChange<'_>> = BTreeMap::new();

    // tx.from always has `account_info_changed` because its nonce is incremented
    let from = account_changes.entry(&tx_caller).or_default();
    from.account_info_changed = true;

    for entry in journal {
        match entry {
            JournalEntry::NonceChange { address } => {
                let account = account_changes.entry(address).or_default();
                account.account_info_changed = true;
            }
            JournalEntry::BalanceTransfer { from, to, .. } => {
                // No need to check balance for 0 value sent, revm does not add it to the journal
                let from = account_changes.entry(from).or_default();
                from.account_info_changed = true;
                let to = account_changes.entry(to).or_default();
                to.account_info_changed = true;
            }
            JournalEntry::StorageChanged { address, key, .. } => {
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
                account.account_info_changed = true;
            }
            JournalEntry::AccountDestroyed {
                address,
                target,
                was_destroyed,
                had_balance,
            } => {
                // This event is produced only if acc.is_created() || !is_cancun_enabled
                // State is not changed:
                // * if we are after Cancun upgrade and
                // * Selfdestruct account that is created in the same transaction and
                // * Specify the target is same as selfdestructed account. The balance stays unchanged.

                if *was_destroyed {
                    // It was already destroyed before in the log, no need to do anything.
                    continue;
                }

                if address != target && !had_balance.is_zero() {
                    // mark changes to the target account
                    let target = account_changes.entry(target).or_default();
                    target.account_info_changed = true;
                }

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

    let mut diff_size = 0usize;

    for (addr, account) in account_changes {
        if account.created {
            diff_size += ACCOUNT_IDX_KEY_SIZE + ACCOUNT_IDX_SIZE;
        }

        // Apply size of account_info
        if account.account_info_changed || account.code_changed {
            let db_account_size = {
                let account = &state[addr];
                if account.info.code_hash == KECCAK_EMPTY {
                    DB_ACCOUNT_SIZE_EOA
                } else {
                    DB_ACCOUNT_SIZE_CONTRACT
                }
            };
            // Account size is added because when any of those changes the db account is written to the state
            // because these fields are part of the account info and not state values
            diff_size +=
                (db_account_size + DB_ACCOUNT_KEY_SIZE) * ACCOUNT_DISCOUNTED_PERCENTAGE / 100;
        }

        // Apply size of changed slots
        let slot_size = STORAGE_KEY_SIZE + STORAGE_VALUE_SIZE; // key + value;

        diff_size +=
            slot_size * account.storage_changes.len() * STORAGE_DISCOUNTED_PERCENTAGE / 100;

        // No checks on code change as it is not part of the state diff
    }

    diff_size
}

// #[cfg_attr(feature = "native", instrument(level = "trace", skip(context)))]
fn change_balance<CTX: ContextTr>(
    context: &mut CTX,
    amount: U256,
    positive: bool,
    address: Address,
) -> Result<Option<InstructionResult>, <<CTX as ContextTr>::Db as Database>::Error> {
    let journaled_state = context.journal();

    let mut account = journaled_state.load_account(address)?;
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
fn decrease_caller_balance<CTX: ContextTr>(
    context: &mut CTX,
    amount: U256,
) -> Result<Option<InstructionResult>, <<CTX as ContextTr>::Db as Database>::Error> {
    let address = context.tx().caller();
    change_balance(context, amount, false, address)
}

#[cfg(feature = "native")]
pub(crate) fn diff_size_send_eth_eoa() -> usize {
    DB_ACCOUNT_KEY_SIZE * ACCOUNT_DISCOUNTED_PERCENTAGE / 100
        + (DB_ACCOUNT_SIZE_EOA + DB_ACCOUNT_KEY_SIZE) * ACCOUNT_DISCOUNTED_PERCENTAGE / 100
}
