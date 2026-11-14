# SP1 proving

Citrea uses SP1 6.10.0 for execution, compressed LCP proving, Groth16 batch proving, and verification. Install the pinned SP1 compiler and Cargo with `make install-sp1`. Native development builds need LLVM Clang with RISC-V support and `protoc`; Docker guest builds also need a running Docker daemon. Guest-only patches use SP1 precompiles for SHA-256, Keccak, secp256k1, P-256, bigint operations, and BN254; their revisions are pinned in each guest lockfile.

## Installing SP1

SP1 needs Git, Rust, Docker, and `protoc`. `make install-sp1` follows SP1's [recommended install](https://docs.succinct.xyz/docs/sp1/getting-started/install), with each download pinned:

- `tools/install-sp1up.sh` is a copy of SP1's installer from `https://sp1up.succinct.xyz`. The only change is `BIN_URL`, which downloads `sp1up` from SP1 commit `d83ed91f` (the `v6.10.0` release) instead of SP1's `main` branch.
- `sp1up --version v6.10.0` installs the `cargo prove` CLI from the `v6.10.0` release, which GitHub marks immutable, and the `succinct` Rust toolchain under `~/.sp1`.
- `tools/verify-sp1-toolchain.sh` checks the toolchain archive against pinned SHA-256 hashes. The toolchain's release in `succinctlabs/rust` is not immutable, and `cargo prove` does not check it. On a mismatch, the script unlinks the toolchain and fails.

The `succinct` toolchain has no Cargo, so the target also installs Rust 1.96.0 to drive guest builds. The installer adds `~/.sp1/bin` to your shell profile; open a new shell, then check the install:

```bash
make install-sp1
cargo prove --version
rustup toolchain list | grep succinct
```

To move to a new SP1 release, copy SP1's current installer into `tools/install-sp1up.sh` and point `BIN_URL` at the release's commit. Then update the toolchain tag and hashes in `tools/verify-sp1-toolchain.sh`; its header has the commands. If GitHub rate-limits the toolchain download, rerun `sp1up --version v6.10.0 --token <github token>`.

## Building guests

Guest compilation is part of the ordinary Cargo build. On macOS, Apple’s system Clang lacks the RISC-V target: install LLVM and set `CC_riscv64im_succinct_zkvm_elf` to its `clang` executable, or use Docker guest builds.

```bash
cargo build --locked -p citrea --features testing
```

For reproducible guests, use SP1's [Docker build](https://docs.succinct.xyz/docs/sp1/writing-programs/compiling#production-builds):

```bash
CITREA_NETWORK=nightly REPR_GUEST_BUILD=1 cargo build --locked -p citrea --features testing
# Release-mode host build with reproducible guests:
CITREA_NETWORK=nightly make build-reproducible
```

The guest crates' build scripts run SP1's [`cargo prove build`](https://docs.succinct.xyz/docs/sp1/writing-programs/compiling) and derive program keys with `cargo prove vkey`. `REPR_GUEST_BUILD=1` builds in SP1's pinned Docker image and requires `CITREA_NETWORK` (`mainnet`, `testnet`, `devnet`, or `nightly`). Native and Docker guest caches are separate, under `guests/sp1/target/elf-compilation/`. The generated ELFs are embedded unchanged; development builds can have different keys across machines.

SP1 6.10 forwards no environment variables into Docker, so Docker builds pass `CITREA_NETWORK` to rustc with `--env-set`; development overrides apply only to native builds. The light-client build script writes the batch program IDs to `guests/sp1/target/batch-proof-ids.rs`, which the batch crate includes inside the light-client guests. C dependencies use Clang with RV64IM flags from `guests/sp1/.cargo/config.toml`, which Cargo also reads inside Docker.

`SKIP_GUEST_BUILD=1` is for static checks: it generates empty development ELFs and zero keys. Tests require real guests. Production networks embed their committed guests even when guest compilation is skipped.

Bitcoin DA batch and light-client ELFs for mainnet, testnet, and devnet are committed under `resources/guests/sp1/<network>/` as `<guest>-<index>.elf`, one per pinned guest version, each with a generated `<guest>-<index>.rs` (ELF include and program ID). `bin/citrea/src/guests.rs` maps each fork to its pins, and the runtime network selects the map. Nightly and custom test networks use the guests built by `cargo build`, as with RISC0, so development overrides work. Mock DA guests are also built locally. The regtest light-client program used by Clementine is the Docker build `CITREA_NETWORK=nightly REPR_GUEST_BUILD=1 cargo build --locked -p citrea-sp1-light-client --features testing`; its ELF is `LIGHT_CLIENT_PROOF-bitcoin.elf` in that crate's build-script output directory.

Regenerate pins with Docker from any supported host:

```bash
python3 tools/pin-sp1-guests.py --network devnet --guest batch-proof --index 0
```

Each run pins one guest (`batch-proof` or `light-client-proof`) of one network (`mainnet`, `testnet`, or `devnet`) under one index. A fork that changes a guest pins it under the next index: add the new module and the fork's entry to `bin/citrea/src/guests.rs`, and list the pin in `crates/sp1/tests/native_keys.rs`. A fork that leaves a guest unchanged maps to the existing pin. To verify the latest pins, run it with each guest's highest index from a clean checkout and then `git diff --exit-code resources/guests/sp1`; lower indexes were built from earlier code. The script always enables Docker, clears development overrides, and writes matching ELFs and constants. Commit the guest's ELF and constants for each changed network and coordinate downstream program-key updates. Native guest builds are for development and must not be used to pin release programs.

Proving modes `prove` and `prove-with-fakes` use Succinct's prover network, authenticated by `NETWORK_PRIVATE_KEY`. `execute` mode, and fake proofs when sampling skips a real proof, execute the real guest and return an explicitly unverified mock envelope; mainnet rejects it. `[sp1_host]` has an optional `tx_backup_dir` and the `[sp1_host.network_request]` settings below.

Requests are priced from the network's suggested price per prover gas unit (PGU), read from `get_proof_request_params` before every submission. A job offers 120% of it, the SDK's default. After each request no prover bids on, the job multiplies its percent by `no_bid_raise_percent` (default 150, env `SP1_NO_BID_RAISE_PERCENT`) up to `max_price_percent` (default 480, env `SP1_MAX_PRICE_PERCENT`), so offers go 120%, 180%, 270%, 405%, 480%, and keeps that percent for the rest of the job. An offer never goes below the job's previous one, and is rounded down to the network's tick and raised to its floor. It never goes above `max_usd_per_billion_pgu` (default 5, env `SP1_MAX_USD_PER_BILLION_PGU`) USD per billion PGU, converted with the PROVE/USD price the prover network reports through its `GetProvePrice` RPC, which the SDK does not wrap; the node calls it on the SDK's RPC (`NETWORK_RPC_URL`, or Succinct's mainnet). The limit covers the price per PGU, not the per-request base fee. While the network's floor is above the limit, or the PROVE price its RPC returns is missing or more than two hours old, the job submits nothing and checks again with backoff, up to every 5 minutes; `sp1_network_usd_limit_holds` counts these waits. When the network gives no positive suggested price, the job retries with backoff three times, then prices without it: the first offer is a quarter of `max_usd_per_billion_pgu`, raised as usual, so the default 480% reaches the limit. The `sp1_network_no_bid_resubmits` counter counts requests no prover bid on; a job at the maximum keeps resubmitting, so a steady rise means a stuck job. Each job executes the guest locally first for its gas, which sets the request deadline: `deadline_percent` (default 100, env `SP1_DEADLINE_PERCENT`) of twice what a 5M PGU/s prover needs, at least 40 minutes, capped at the network's 24 hours. Provers only bid on requests they expect to finish in time, so raise it if requests go unclaimed at the maximum price. Requests wait `auction_timeout_secs` (default 60, env `SP1_AUCTION_TIMEOUT_SECS`) to be assigned, and none is assigned within `min_auction_period_secs` (default 15, env `SP1_MIN_AUCTION_PERIOD_SECS`) of its submission: the auction settles once that period has passed and a prover has bid. A prover in `prove` or `prove-with-fakes` mode refuses to start without a valid `NETWORK_PRIVATE_KEY`, with `no_bid_raise_percent` not above 100, `max_price_percent` below 120, `max_usd_per_billion_pgu` not above 0, `deadline_percent` of 0, or an auction timeout not longer than the minimum auction period, which would cancel every request before it could be assigned; unparsable env values stop the node too. Mainnet rejects mock proofs, so a mainnet prover also refuses to start in `execute` mode, or in `prove-with-fakes` mode with a proof sampling number above 1, which fakes all but one in that many proofs; 0 and 1 prove every job. These settings apply at startup, so changing them takes a restart. A claimed request the network expires undelivered is resubmitted with twice the deadline, up to 24 hours. A deadline that has passed only by the node's clock does not count: the job keeps polling until the network fulfills or expires the request. A request is unfulfillable when the prover that won its auction reports that it cannot prove it, optionally with a reason (`ProofRequestError`). The SDK sees only the status, so the node reads the reason from the request's details. The guest has already executed locally, so the cause is usually that prover, such as a crash or a wrong SP1 version, and another prover may succeed. The request is resubmitted with backoff, at most three times per job, after which the job ends, since a cause in the input itself fails every prover. `sp1_network_unfulfillable_requests` counts these by reason, such as `PROVING_FAILURE` or `VERIFICATION_KEY_MISMATCH`; `UNSPECIFIED_PROOF_REQUEST_FAILURE` when the prover gave none, and `UNKNOWN` when the node could not read it. Requests go to the SDK's default set of provers with reliable uptime, so a prover that did not deliver can win the next auction too. After an undelivered or unfulfillable request, the job therefore requests only from the network's high-availability provers for the rest of the job, as the SDK's own requests do once; when the network lists none, or cannot be asked, it keeps the default set and asks again after the next such request. `sp1_network_high_availability_fallbacks` counts the jobs that switch. Failed uploads, and RPC errors with a transient status (unavailable, deadline exceeded, internal, aborted, cancelled, or unknown, which a connection dropped mid-call reports), are retried with backoff. Any other RPC status before the network accepts a request ends the job, including one from `GetProvePrice`. Once the network has accepted a request, only its terminal states end it: any other failure to get its status or download its proof polls the same request again, so one proof is not paid for twice, and the job ends after an hour of such failures with no successful poll between them. Guest execution failures, reverted settlements, a proof whose public values differ from the local execution and a proof that fails local verification end the job too. The light client prover then retries its L1 block with a new job after a minute, doubling the wait after each failure of the same block in a row up to an hour, and counts the failures in `light_client_prover_failed_l1_block_attempts`; the batch prover reschedules the job when it next starts.

For local e2e tests, use `proving_mode = "execute"` and set `PARALLEL_PROOF_LIMIT=1`.

`make test-succinct-network` runs two ignored e2e tests against the prover network itself: one batch proof (about 0.4 PROVE), and light client proofs for every L1 block up to a batch proof (a few PROVE). Name one to run it alone, e.g. `make test-succinct-network succinct_network_batch_proof`. Set `NETWORK_PRIVATE_KEY` to a funded requester account. On macOS, guest builds also need `CC_riscv64im_succinct_zkvm_elf` set to a Clang with RISC-V support, such as Homebrew's `llvm@19`.

The batch/mock Borsh proof envelopes are `Groth16 { proof: Vec<u8>, public_values: Vec<u8> }` (variant 0) or `Mock { program: [u32; 8], public_values: Vec<u8> }` (variant 1). Compressed LCPs use variant 3, described in the recursion document. A Groth16 proof contains SP1's four-byte verifier selector, three 32-byte fields (exit code, recursion-key root, proof nonce), and the 256-byte Groth16 proof. Verification binds both the trusted program key and the complete public values. Mock envelopes require explicit verification opt-in and must match the expected program.

Program IDs are the eight canonical KoalaBear words returned by `SP1VerifyingKey::hash_u32()`, stored directly as `[u32; 8]`. They are not hashes of ELF files. The encodings at each boundary are:

| Boundary | Encoding |
| --- | --- |
| Native recursion and Rust program IDs | Eight canonical `u32` words, each less than `0x7f000001` |
| Borsh receipts, storage, circuit I/O, signed DA method-ID update bodies, and RPC method-ID hex | Eight little-endian `u32` words |
| `BATCH_PROOF_METHOD_ID` | Eight big-endian `u32` words, matching `hash_bytes()` |
| Groth16 verifier and `cargo prove vkey` | Big-endian bytes of the base-2^31 packed digest, matching `bytes32()` |

Guest build scripts unpack `cargo prove vkey` output into the native digest without compiling the SDK as a build dependency. The light-client build embeds the batch-program key generated by the same build. `BATCH_PROOF_METHOD_ID` overrides take native digest hex, not the packed `bytes32` hash. `CITREA_NETWORK` selects the local development guest build; production guest selection uses the committed pins for the runtime network.

RPC method-ID hex (`getBatchProofMethodIds`, and `lightClientProofMethodId` in light client proof outputs) is the method ID's Borsh bytes, so it is byte-for-byte the first 32 bytes of a signed DA method-ID update body. A key taken from `hash_bytes()` or `BATCH_PROOF_METHOD_ID` must have each 4-byte word reversed before use in an update body.

This changes the proof wire format and all program commitments. Existing stored proofs and published commitments are incompatible. Networks proven with RISC0 continue from a RISC0 cutoff, see [Existing-network activation](#existing-network-activation).

Provers store an SP1 proving session info returned as `info` by the proof RPCs and as `sessionInfo` by `batchProver_getLatestProvingSessionInfos`. Both variants carry the execution stats of the guest's local run: `instruction_count`, `syscall_count`, and `gas` in PGU, all from SP1's execution report. `execute` mode and fake proofs without a network proof record `LocalExecution`. Network proofs record `SuccinctNetwork` with the hex `request_id`, the execution stats, and `fulfillment`, the network's record of the request fetched after delivery: `gas_used`, `gas_price` (the auction's clearing price, in PROVE wei per PGU), `base_fee` (PROVE wei, as a decimal string), and the Unix-second `created_at` and `fulfilled_at`. The request's fee is `base_fee + gas_used * gas_price`. `fulfillment` is null when the network does not return the request; the proof is kept either way.

Every guest execution sets the `sp1_execution_instruction_count`, `sp1_execution_syscall_count`, and `sp1_execution_gas` Prometheus gauges, replacing RISC Zero's `proving_session_cycle_count`. Delivered network requests set `sp1_network_gas_price` (PROVE per billion PGU) and record `sp1_network_request_duration_secs`, from creation to fulfillment. The bundled Grafana dashboards chart them.

See [native LCP recursion](sp1-recursion.md) for compressed LCP transport and terminal Groth16 proofs.

Containerized SP1 execution needs more shared memory than Docker's default `/dev/shm`; `docker run --shm-size=8g` is known to work.

## Compatibility

On existing prover databases, the `drop_legacy_proving_sessions` ledger migration drops the old session-info and Bonsai/Boundless recovery column families without decoding them. Session-info tables are recreated empty for SP1 statistics; stored proofs and rollup state are unchanged.

On existing sequencer, full node and batch prover databases, the `reencode_short_header_proofs` ledger migration rewrites the short header proofs v2.10 cached, whose coinbase transaction encoding changed. It decodes them the v2.10 way and needs no Bitcoin RPC access.

The EIP-2537 BLS12-381 precompiles are removed for all specs, independent of Pomelos's L2 activation height. No deployed network has historical calls to them, so replay does not need their implementation.

## Existing-network activation

Mainnet, testnet, and devnet were proven with RISC0. SP1 proving continues from a
RISC0 cutoff: `L0` is a chosen L1 checkpoint while RISC0 proving is still running, and
`P0` is the RISC0 light client proof output at `L0`. P0 lives in
`crates/primitives/src/risc0_cutoff.rs` with every field of the output except the
RISC0 light client method ID: its DA state (L0's Bitcoin header chain state, whose
height is `L0`), L2 state root, last L2 height, last sequencer commitment index, and
light client JMT root. The light client guest's compiled initial values (the initial
DA state, L2 genesis root, and initial batch proof method IDs) are only used by a light
client that starts from genesis, so they stay unchanged. Nodes refuse to start on these networks
while their cutoff is unset. Setting a cutoff changes the guests, so refresh the pins
afterwards.

Until the checkpoints are chosen, each network's `*_RISC0_CUTOFF` remains `None`.
Fill it with `Some(Risc0Cutoff { da_state, l2_state_root, last_l2_height,
last_sequencer_commitment_index, lc_state_root })`, copied from P0's journal. The
circuit only checks part of them: `L0 + 1`'s header must follow the DA state, but its
total work and epoch start time carry over into later light client proofs as they are,
and a wrong last L2 height is reported until a commitment chains. The
V3 entries in `crates/primitives/src/forks.rs` separately hold the scheduled L2
activation heights; `u64::MAX` keeps them inactive until configured.

Rollout:

1. Choose `L0` and obtain `P0` from the existing RISC0 LCP. RISC0 batch proving
   stops at P0: no RISC0 batch proof is published after it.
2. Set the network checkpoint and schedule V3 at a future L2 height. Rebuild
   and pin the SP1 guests with these constants, then release the v3 binary.
3. Start the v3 SP1 LCP and batch prover; the RISC0 LCP is no longer needed.
   The SP1 LCP runs on the database the RISC0 LCP left and advances L1 from `L0 + 1`.
   The security council adds the SP1 batch key to the light client (see below). The
   SP1 batch prover backfills the commitments after P0, allowing the SP1 LCP to
   advance L2.
4. All Clementine signers update, and the funds are moved.
5. Boundless shuts down. V3's L2 behavior can activate before or after that
   shutdown; the SP1 ELF already includes its rules.

The batch explorer must switch its verifier and program keys to SP1 in its own
deployment. Coordinate these deployments manually with the Clementine operators.

`SpecId::Pomelo` activates the V3 execution rules at a separately scheduled L2 height.
The SP1 batch guest proves every L2 block after `P0.last_l2_height`, including the
blocks before V3's activation, so batch provers and full nodes always use
V3's guest after the cutoff. The light client likewise always uses V3's guest.

- Light client prover: the first SP1 proof is for `L0 + 1` and has no previous proof.
  The guest uses P0, compiled in, as its previous output: it verifies `L0 + 1`'s header
  against P0's DA state, so no other L1 block can start from P0, and continues P0's
  L2 state and JMT. The JMT already holds the commitments, proofs, and L1 hashes seen
  up to `L0`. Start the prover on the RISC0 light client prover database: either stop
  the RISC0 prover right after it proves `L0`, or roll its database back to `L0` with
  `citrea-cli rollback --node-type light-client-prover --l1-target <L0>`. Keep
  `initial_da_height` (`INITIAL_DA_HEIGHT`) unchanged: at `L0 + 1` the prover finds the
  RISC0 proof of `L0` and starts the SP1 chain from P0 instead, and it refuses an L0
  without a stored proof.
- Light client batch proof method IDs: P0's JMT keeps the RISC0 ones, so after `L0`
  the security council must add the SP1 batch key with a batch proof method ID
  transaction for the network's chain ID, with activation height
  `P0.last_l2_height`. Every proof the light client can accept after P0 ends after
  `P0.last_l2_height`, so the RISC0 keys are never selected again. The height must
  be above the last activation height in P0's JMT, including RISC0 upgrades scheduled
  after P0: otherwise the transaction is rejected, so choose an `L0` whose
  `P0.last_l2_height` is above every scheduled activation height.
  Confirm the transaction before the first SP1 batch proof, or earlier in the same
  block. The light client rejects SP1 batch proofs that it processes before it and
  never reconsiders them, so the batch prover would have to publish them again.
- Batch prover: proves commitments after `P0.last_sequencer_commitment_index`. It needs
  the two commitments up to P0 as previous commitments, so scan L1 from a height at or
  before the one that contains commitment `P0.last_sequencer_commitment_index - 1`.
  Pending commitments up to P0 are dropped. A v2 batch prover database can still hold
  a RISC0 proof of commitments after P0 that it never published, which v3 would
  publish on start. Roll it back with
  `citrea-cli rollback --node-type batch-prover --sequencer-commitment-index <P0 index>
  --l1-target <last L1 block before commitment P0 index + 1>` so they are scanned again
  and proved with SP1.
- Full node upgraded from v2: stop v2 and start v3 on the same database, without a
  rollback. v2 can't read SP1 batch proofs and discards them, so on its first start v3's
  `rescan_l1_after_risc0_cutoff` ledger migration moves the L1 scan of a database past
  `L0` back to `L0`, and the node reads them again. It keeps everything else v2 stored:
  commitments, pending commitments and proofs, and the proven heights of the RISC0
  proofs v2 verified. The rescan records its committed and proven heights at L1 heights
  no lower than v2's latest status rows, so `citrea_getL2StatusHeightsByL1Height`
  reports them from those L1 heights. v2 stops
  syncing L2 at the first block whose state root V3's rules change, so a node that
  reaches V3's activation height first waits there until it runs v3. Don't roll the full
  node back to `L0`: that deletes the heights of proofs found up to `L0` but accepted
  after it, which the rescan can't restore.
- Full node syncing from scratch: batch proofs found up to `L0` are RISC0 proofs. They
  are accepted on the batch prover's DA signature without verification. To verify
  them, run v2 up to `L0` and then update to v3.

Tests pass synthetic cutoffs directly: the light client circuit tests
(`crates/light-client-prover/src/tests/risc0_cutoff.rs`), and the input builder,
batch prover, and full node unit tests.
