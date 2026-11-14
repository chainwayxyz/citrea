# Header consensus differential tests

This is a **test-only** workspace. Neither guest nor application depends on it.
`build.rs` reads the selected Citrea and Clementine verifier files and extracts
function bodies, rather than testing a separate shared implementation. It also
reads Clementine's network constants. The only function edit is test visibility.
Network selection is supplied through the typed build-network constant or the
`BITCOIN_NETWORK`/`get_network()` configuration, matching the selected source.
The C++ fixture calls unmodified Bitcoin Core v29.0 functions; the build refuses
a different Core revision or modified tracked Core sources. rust-bitcoin is
pinned to 0.32.102, the version in both migration branches' lockfiles.

## Run

From the Citrea root, with a clean Core v29.0 checkout and the Clementine PR
checkout available (Rust 1.97, a C++20 compiler and Git are required):

```sh
BITCOIN_CORE_SOURCE=/path/to/bitcoin-core-v29 \
CLEMENTINE_SOURCE=/path/to/clementine \
PROPTEST_CASES=1000000 PROPTEST_RNG_SEED=20261103 \
cargo test --locked --release --manifest-path tests/header-consensus/Cargo.toml
```

The Core commit is `f490f5562d4b20857ef8d042c050763795fd43da`.
`CITREA_SOURCE` optionally selects another Citrea checkout; by default the test
uses the containing repository. Each of six property tests runs one million
cases with these settings. Proptest shrinks failures and saves seeds in
`proptest-regressions`; review a minimized input and promote it to a named
regression before committing it. This is property-based differential fuzzing,
not a coverage-guided libFuzzer campaign.

Coverage:

- Arbitrary compact encodings, including negative, overflowing and tiny targets;
  decode and block-work results against Core's `SetCompact`/`GetBlockProof`.
- Arbitrary 256-bit targets: compact encoding against Core and rust-bitcoin;
  work against rust-bitcoin where the APIs agree.
- Valid-target retargets with arbitrary timestamp pairs on mainnet, Testnet4
  and Citrea's ten-second custom signet, plus exact clamp-boundary regressions.
- MTP with 1–11 predecessors against Core's `GetMedianTimePast`. Citrea's
  fixed-history helper is compared with 11 predecessors, matching its normal
  checkpoint use; this does not assert identical early-chain bootstrap policy.
- PoW comparison against Core and rust-bitcoin on all four network limits;
  both production comparison functions must accept a hash equal to its target.
- Testnet4 epoch timewarp boundaries in Clementine. These assertions use the
  explicit BIP94 inequality plus Core MTP; they do **not** invoke Core's full
  `ContextualCheckBlockHeader`.

## Historical migration-branch counterexamples

These are historical pre-fix baselines, not the current default branches.
Clementine main at `fef6ecf31ad1786aa269567f58d37c82303ba2ea` already contains
the saturating-subtraction fix and its regression test; the new PR retains them.
For reproducible counterexamples, select detached worktrees at:

- Citrea `88a532c94a0b1562851e55e84bdeebfe5248c33d`;
- Clementine `0ef00bb8611e473d7f688c7cb1d57408e3a79c93`.

Set one source variable to its baseline while keeping the other at its corrected
PR version. Failure is expected. This isolates each implementation rather than
letting the first failing assertion hide the other one's disagreement.

Concrete baseline results:

- Both retarget implementations use unsigned subtraction. With bits `0x1c123456`,
  first time `2000000` and last time `1000000`, the release build computes
  `0x1c48d158`, while Core computes `0x1c048d15`. Debug builds can panic instead.
- Clementine's baseline full-array MTP accepts time `100` after the sole
  predecessor at time `100` because ten unused zeros enter the median. Core
  rejects equality. The baseline adapter deliberately calls its existing
  `validate_timestamp` helper without adding missing height-aware behavior.
- The same adapter exposes the missing BIP94 epoch guard at the 600-second
  boundary. Existing PR module tests cover Testnet4 minimum-difficulty timestamp
  overflow through the real verifier entry points.
- Tiny/extreme compact targets and target-one work also disagree. These are
  arithmetic edge cases, not proof that they are reachable from the configured
  production checkpoints.

## Why "exactly the same as Core and rust-bitcoin" is not the test contract

Pinned rust-bitcoin itself differs from Core: target `1` has work `U256::MAX`
in its API, versus `2^255` in Core; target zero also differs. Its compact API
has no Core-style overflow/negative flags (e.g. `0x01810000` differs). Its
`from_header_difficulty_adjustment` helper also subtracts timestamps unsigned.
The suite explicitly asserts these discrepancies. For the unsigned elapsed-time
retarget API, tests normalize a negative signed difference to zero before the
call; they do not pretend the raw header helper agrees.

A one-line correction before the existing minimum-timespan clamp is justified
**in both** implementations:

```rust
let mut actual_timespan = last_timestamp.saturating_sub(epoch_start_time);
```

With the existing positive lower clamp, saturating a negative elapsed time to
zero produces the same result as Core's signed subtraction followed by clamping.
The original `target_to_bits` algorithm is also retained: only its four output
assignments change, to handle zero and out-of-range byte indices. Clementine's
contextual timestamp checks stay in its existing functions; no production
functions are added.

That fixes retarget timing only, not all other differences. These tests also do
not prove equivalence of full state transitions, accumulated-work policies,
checkpoint trust, version deployments, wall-clock checks, signet challenges,
transactions, or SP1 execution/ELFs. Citrea's zero regtest work and saturating
accumulated work remain different from Clementine/Core. No guest artifacts are
rebuilt by this test workspace.
