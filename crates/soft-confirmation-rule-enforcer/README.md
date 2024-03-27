## Soft Confirmation Rule Enforcer

Implementation of Citrea's soft confirmaiton rules as a Sovereign SDK Module.

This module can be used in any `State Transition Function` to enforce two rules:
- **Block Count Rule**: A sequencer cannot publish more L2 blocks on a single L1 block than the amount set by the rollup.
- **Fee Rate Rule**: Between two consecutive L2 blocks, a sequencer cannot increase or decrease the L1 fee rate more thant the amount set by the rollup.