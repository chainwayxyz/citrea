## Citrea STF

This is the State Transition Function crate for the Citrea rollup.

The Citrea State Transition Function consists of 3 modules:
- [EVM](../evm/README.md): Used for handling EVM functionality.
- [sov-accounts](../sovereign-sdk/module-system/module-implementations/sov-accounts/README.md): Used for checking the sequencer's nonce.
- [L2 Block Rule Enforcer](../l2-block-rule-enforcer/README.md): Used for enforcing Citrea's l2 block rules..


Through applying transaction/blob/l2 block hooks (see [`hooks_impl.rs`](./src/hooks_impl.rs)), it runs the rollup via the [`Runtime`](./src/runtime.rs).
