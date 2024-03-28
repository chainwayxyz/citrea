## Sequencer

This crate defines the behaviour of Citrea sequencer.

The crate is also responsible for Citrea's mempool and serving necessary information for full nodes to sync.

Contrary to full nodes, the `CitreaSequencer` does not use the `StateTransitionFunction::apply_soft_batch` function, instead it drives the [`State Transition Function`](/crates/citrea-stf/README.md) using its inner functions. This gives the sequencer to see the results of transactions, without making a pending soft confirmation available to other nodes.
