//! Bounds the amount of memory a single tracing request may retain.
//!
//! Tracing inspectors accumulate the whole transaction in memory: the structlog tracer keeps one
//! [`CallTraceStep`] per executed opcode, optionally with a copy of the stack, the memory and the
//! returndata of that step. A single transaction with a 30M gas limit can execute ~10M opcodes, so
//! an unbounded trace can retain multiple gigabytes.
//!
//! [`TraceMemoryLimiter`] wraps the real inspector and charges every recorded step and call frame
//! against a byte budget. Once the budget is exhausted, execution is aborted the same way a
//! database error aborts it: by setting [`ContextError::Custom`] on the context and returning
//! [`InstructionResult::FatalExternalError`] from the inspector. The revm interpreter loop breaks
//! out as soon as the inspector returns, and the handler turns the context error into
//! `EVMError::Custom` (which maps to `EthApiError::EvmCustom`), so the caller gets a regular RPC
//! error.
//!
//! The budget is an estimate of the bytes the tracer *retains*, derived from the tracer config and
//! the interpreter state, not a measurement of the process heap. It does not see allocations we
//! cannot attribute to a step or a frame - most notably the heap of a JS tracer, whose accounting
//! would require allocator level tracking.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};

use revm::bytecode::opcode;
use revm::context::ContextTr;
use revm::context_interface::context::ContextError;
use revm::inspector::JournalExt;
use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::interpreter_types::{Jumps, LoopControl, ReturnData};
use revm::interpreter::{
    CallInputs, CallOutcome, CreateInputs, CreateOutcome, EOFCreateInputs, InstructionResult,
    Interpreter,
};
use revm::primitives::{Address, Log, U256};
use revm::{Inspector, JournalEntry};
use revm_inspectors::tracing::types::{CallLog, CallTraceNode, CallTraceStep};
use revm_inspectors::tracing::TracingInspectorConfig;

/// Bytes an [`U256`] stack item occupies in a recorded stack snapshot.
const STACK_ITEM_SIZE: usize = 32;

/// Bytes a 32 byte word of EVM memory occupies in the geth struct log the trace is converted into:
/// a `String` header in a `Vec<String>` plus its 64 character hex allocation.
///
/// The arena shares one reference counted memory snapshot between steps that did not write to
/// memory, but the struct log builder materializes its own copy for *every* step, so this is
/// charged per step regardless.
const MEMORY_STRUCT_LOG_WORD_SIZE: usize = 88;

/// Bytes a storage slot occupies in the `BTreeMap` a struct log carries.
const STORAGE_ENTRY_SIZE: usize = 64;

/// The error message a trace is rejected with once it exceeds the memory limit of `limit` bytes.
pub fn trace_memory_limit_exceeded(limit: usize) -> String {
    format!("tracing this transaction exceeded the memory limit of {limit} bytes")
}

/// The running total of one *request*, shared by every transaction it traces.
///
/// `debug_traceBlock*` traces a whole block, and while the arena of each transaction is dropped
/// once its trace is built, the built traces are all retained until the response is sent. A budget
/// per transaction would therefore bound nothing for a block full of them.
#[derive(Debug)]
pub(crate) struct TraceMemoryUsage {
    /// Budget in bytes, [`None`] if tracing is unlimited.
    limit: Option<usize>,
    used: Cell<usize>,
}

/// Converts a megabyte budget to bytes, clamped to at most 1 TiB. The clamp keeps `* 1024 * 1024`
/// from overflowing `u64` - which wraps in release builds (silently disabling the bound) and panics
/// in debug builds - and bounds a misconfigured value to a sane maximum. Used by the trace memory
/// budget here and by the trace cache in `ethereum-rpc`.
pub const fn mb_to_bytes(limit_mb: u64) -> usize {
    const MAX_LIMIT_MB: u64 = 1 << 20; // 1 TiB
    let limit_mb = if limit_mb > MAX_LIMIT_MB {
        MAX_LIMIT_MB
    } else {
        limit_mb
    };
    (limit_mb * 1024 * 1024) as usize
}

impl TraceMemoryUsage {
    pub(crate) fn new(limit_mb: u64) -> Self {
        Self {
            limit: (limit_mb > 0).then(|| mb_to_bytes(limit_mb)),
            used: Cell::new(0),
        }
    }

    /// Add to the running total. Used both by the per-step limiter and to charge a prestate or
    /// flat-call response, which is built after execution and so is never charged per step.
    pub(crate) fn charge(&self, bytes: usize) {
        self.used.set(self.used.get().saturating_add(bytes));
    }

    /// The limit, if it has been exceeded.
    fn exceeded(&self) -> Option<usize> {
        self.limit.filter(|limit| self.used.get() > *limit)
    }

    /// Bytes still available before the budget is hit, or [`None`] if tracing is unlimited. Used to
    /// bound a prestate or flat-call response, which is built after execution and is never charged
    /// per step.
    pub(crate) fn remaining(&self) -> Option<usize> {
        self.limit
            .map(|limit| limit.saturating_sub(self.used.get()))
    }

    /// The error message for a response that outgrew [`Self::remaining`]. It names the configured
    /// limit rather than that residual, which depends on what the request had already retained.
    pub(crate) fn response_too_large(&self) -> String {
        trace_memory_limit_exceeded(self.limit.unwrap_or_default())
    }
}

/// What a tracer retains per step and per call frame, and the request total to charge it against.
///
/// Build it with [`TraceMemoryBudget::steps`] for a [`TracingInspector`] driven tracer, whose cost
/// follows from its [`TracingInspectorConfig`]; [`TraceMemoryBudget::call_frames`] for one that
/// builds a call trace arena without opcode level steps; or [`TraceMemoryBudget::opaque`] for one
/// that retains nothing we can attribute to a frame.
///
/// [`TracingInspector`]: revm_inspectors::tracing::TracingInspector
#[derive(Clone, Copy, Debug)]
pub(crate) struct TraceMemoryBudget<'a> {
    usage: &'a TraceMemoryUsage,
    /// Bytes retained by the [`CallTraceStep`] record itself, zero if steps are not recorded.
    step_base: usize,
    /// Whether a memory snapshot is retained per step.
    record_memory: bool,
    /// Whether a stack snapshot is retained per step.
    record_stack: bool,
    /// Whether a returndata snapshot is retained per step.
    record_returndata: bool,
    /// Whether steps record storage changes. The struct log builder gives every such step a copy
    /// of *all* storage of that contract seen so far, so the cost is quadratic in storage ops.
    record_storage: bool,
    /// Whether a [`CallTraceNode`], and the call data it holds on to, is retained per frame.
    record_frames: bool,
    /// Whether each emitted log (its data and topics) is retained in the frame. Set from
    /// `TracingInspectorConfig::record_logs`, i.e. the call tracer's `withLog`.
    record_logs: bool,
}

impl<'a> TraceMemoryBudget<'a> {
    /// Budget for a tracer that records opcode level steps as configured by `config`.
    pub(crate) fn steps(usage: &'a TraceMemoryUsage, config: &TracingInspectorConfig) -> Self {
        // `record_logs` is independent of `record_steps`: the call tracer records logs but no
        // steps, so it must survive the early return below.
        let base = Self {
            record_logs: config.record_logs,
            ..Self::call_frames(usage)
        };
        if !config.record_steps {
            return base;
        }
        Self {
            step_base: std::mem::size_of::<CallTraceStep>(),
            record_memory: config.record_memory_snapshots,
            record_stack: config.record_stack_snapshots.is_full()
                || config.record_stack_snapshots.is_all(),
            record_returndata: config.record_returndata_snapshots,
            record_storage: config.record_state_diff,
            ..base
        }
    }

    /// Budget for a tracer that builds a call trace arena but no opcode level steps, such as the
    /// call, flat call, prestate and mux tracers.
    pub(crate) fn call_frames(usage: &'a TraceMemoryUsage) -> Self {
        Self {
            usage,
            step_base: 0,
            record_memory: false,
            record_stack: false,
            record_returndata: false,
            record_storage: false,
            record_frames: true,
            record_logs: false,
        }
    }

    /// Budget for a tracer that retains nothing per completed frame.
    ///
    /// The four byte tracer keeps only a map of selectors, and the JS tracer pushes a frame on
    /// entry and pops it on exit, so charging either for the call data of every call made would
    /// abort traces that are holding almost nothing. Note that this leaves a JS tracer effectively
    /// unbounded: what it retains lives in its own JS heap, which this model cannot see.
    pub(crate) fn opaque(usage: &'a TraceMemoryUsage) -> Self {
        Self {
            record_frames: false,
            ..Self::call_frames(usage)
        }
    }

    /// Whether the retained total has passed the budget. `step` is the only hook that aborts, so
    /// charges that land after the last step - notably the root frame's retained output in
    /// `call_end`, with no parent step to follow it - are never rejected mid-execution. Callers
    /// check this once after execution to catch that overshoot.
    pub(crate) fn exceeded(&self) -> Option<usize> {
        self.usage.exceeded()
    }
}

/// Aborts the traced transaction once its tracer has retained more than the configured number of
/// bytes. See the [module docs](self) for the mechanism.
pub(crate) struct TraceMemoryLimiter<'a, I> {
    inner: I,
    budget: TraceMemoryBudget<'a>,
    /// Whether the previously executed opcode wrote to memory. The tracer only allocates a new
    /// memory snapshot in that case, otherwise it clones the reference counted snapshot of the
    /// previous step.
    memory_dirty: bool,
    /// Opcode of the step currently in flight, needed to attribute a storage change in `step_end`.
    current_op: u8,
    /// Storage slots seen per contract, mirroring the map the struct log builder accumulates and
    /// copies into every step that changes storage.
    storage_slots: HashMap<Address, HashSet<U256>>,
}

impl<'a, I> TraceMemoryLimiter<'a, I> {
    pub(crate) fn new(inner: I, budget: TraceMemoryBudget<'a>) -> Self {
        Self {
            inner,
            budget,
            // the first step of every frame allocates a snapshot of its own
            memory_dirty: true,
            current_op: opcode::STOP,
            storage_slots: HashMap::new(),
        }
    }
}

impl<I, CTX> Inspector<CTX, EthInterpreter> for TraceMemoryLimiter<'_, I>
where
    CTX: ContextTr<Journal: JournalExt>,
    I: Inspector<CTX, EthInterpreter>,
{
    fn initialize_interp(&mut self, interp: &mut Interpreter, context: &mut CTX) {
        self.inner.initialize_interp(interp, context)
    }

    fn step(&mut self, interp: &mut Interpreter, context: &mut CTX) {
        self.inner.step(interp, context);

        let mut cost = self.budget.step_base;
        if self.budget.record_stack {
            // once in the arena, once more in the struct log the trace is converted into
            cost += 2 * interp.stack.len() * STACK_ITEM_SIZE;
        }
        if self.budget.record_memory {
            let memory = interp.memory.borrow().context_memory().len();
            if self.memory_dirty {
                cost += memory;
            }
            cost += memory / STACK_ITEM_SIZE * MEMORY_STRUCT_LOG_WORD_SIZE;
        }
        if self.budget.record_returndata {
            cost += interp.return_data.buffer().len();
        }
        self.budget.usage.charge(cost);

        let op = interp.bytecode.opcode();
        self.current_op = op;
        // mirrors the snapshot reuse in `TracingInspector::start_step`
        self.memory_dirty =
            revm::bytecode::opcode::OpCode::new(op).is_some_and(|op| op.modifies_memory());

        if let Some(limit) = self.budget.usage.exceeded() {
            *context.error() = Err(ContextError::Custom(trace_memory_limit_exceeded(limit)));
            interp
                .control
                .set_instruction_result(InstructionResult::FatalExternalError);
        }
    }

    fn step_end(&mut self, interp: &mut Interpreter, context: &mut CTX) {
        // A step that changed storage carries a copy of every slot of its contract seen so far
        // into the struct log (`geth_call_traces`'s `contract_storage.clone()`), so the cost of
        // one step grows with the number of storage ops before it. Mirrors the condition in
        // `TracingInspector::fill_step_on_step_end`, which is the only thing that populates the
        // map being copied.
        if self.budget.record_storage && matches!(self.current_op, opcode::SLOAD | opcode::SSTORE) {
            if let Some(JournalEntry::StorageChanged { address, key, .. }) =
                context.journal_ref().last_journal().last()
            {
                let slots = self.storage_slots.entry(*address).or_default();
                slots.insert(*key);
                let charge = slots.len() * STORAGE_ENTRY_SIZE;
                self.charge(charge);
            }
        }

        self.inner.step_end(interp, context)
    }

    fn log(&mut self, interp: &mut Interpreter, context: &mut CTX, log: Log) {
        if self.budget.record_logs {
            // A call tracer with `withLog` keeps each log - its data and topics - in the frame for
            // the life of the trace, so a log flood would otherwise exceed the budget uncharged.
            // The next `step`, or the post-execution re-check, enforces the limit against this.
            self.charge(
                std::mem::size_of::<CallLog>()
                    + log.data.data.len()
                    + log.data.topics().len() * STACK_ITEM_SIZE,
            );
        }
        self.inner.log(interp, context, log)
    }

    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        self.charge_frame(inputs.input.len());
        self.inner.call(context, inputs)
    }

    fn call_end(&mut self, context: &mut CTX, inputs: &CallInputs, outcome: &mut CallOutcome) {
        if self.budget.record_frames {
            self.charge(outcome.result.output.len());
        }
        // The tracer looks at the last step of the *parent* frame, which is now the call opcode
        // itself, and the whole call family is in `OpCode::modifies_memory`. So the parent's next
        // step allocates a fresh snapshot rather than reusing one, whatever this frame executed.
        self.memory_dirty = true;
        self.inner.call_end(context, inputs, outcome)
    }

    fn create(&mut self, context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        self.charge_frame(inputs.init_code.len());
        self.inner.create(context, inputs)
    }

    fn create_end(
        &mut self,
        context: &mut CTX,
        inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if self.budget.record_frames {
            self.charge(outcome.result.output.len());
        }
        // unlike the call family, `CREATE` and `CREATE2` are not in `OpCode::modifies_memory`, so
        // the parent's next step reuses the snapshot taken before the create
        self.memory_dirty = false;
        self.inner.create_end(context, inputs, outcome)
    }

    fn eofcreate(
        &mut self,
        context: &mut CTX,
        inputs: &mut EOFCreateInputs,
    ) -> Option<CreateOutcome> {
        self.charge_frame(0);
        self.inner.eofcreate(context, inputs)
    }

    fn eofcreate_end(
        &mut self,
        context: &mut CTX,
        inputs: &EOFCreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if self.budget.record_frames {
            self.charge(outcome.result.output.len());
        }
        // `EOFCREATE` is in `OpCode::modifies_memory`
        self.memory_dirty = true;
        self.inner.eofcreate_end(context, inputs, outcome)
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        self.inner.selfdestruct(contract, target, value)
    }
}

impl<I> TraceMemoryLimiter<'_, I> {
    /// Charges `bytes` without checking the budget. Only [`Inspector::step`] can check it, because
    /// aborting needs an interpreter to halt; the overshoot is bounded by a single frame since
    /// every frame is entered and left from a step of its parent.
    fn charge(&mut self, bytes: usize) {
        self.budget.usage.charge(bytes);
    }

    /// Charges the trace node a tracer retains for a call frame, along with the `input_len` bytes of
    /// call data it keeps a reference to. A call sourcing its input from memory allocates a fresh
    /// copy of it (`Bytes::copy_from_slice` in revm's call helpers) that stays alive for as long as
    /// the trace does, which is what lets a loop of large calls exhaust memory in frames alone.
    fn charge_frame(&mut self, input_len: usize) {
        if self.budget.record_frames {
            self.charge(std::mem::size_of::<CallTraceNode>() + input_len);
        }
        // a new frame has its own memory, so its first step allocates a snapshot
        self.memory_dirty = true;
    }
}

#[cfg(test)]
mod limit_conversion_tests {
    use super::{mb_to_bytes, TraceMemoryUsage};

    #[test]
    fn trace_memory_limit_is_clamped_and_never_overflows() {
        // 0 disables the limit entirely.
        assert!(TraceMemoryUsage::new(0).limit.is_none());
        // A normal value converts straight to bytes.
        assert_eq!(TraceMemoryUsage::new(512).limit, Some(512 * 1024 * 1024));
        // An overflowing / absurd value is clamped to 1 TiB, not wrapped or panicking.
        assert_eq!(mb_to_bytes(u64::MAX), (1usize << 20) * 1024 * 1024);
        assert_eq!(
            TraceMemoryUsage::new(u64::MAX).limit,
            Some((1usize << 20) * 1024 * 1024)
        );
    }
}
