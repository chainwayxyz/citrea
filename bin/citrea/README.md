## Citrea Rollup

This crate is the starting point of the Citrea rollup. It conenects the State Transition Function, configurations, and RPC functionality.

The `start_rollup` function glues everything together and yields execution to either `CitreaSequencer::run` function, if run as sequencer, or to `StateTransitionRunner::run_in_process` function, if run as full node.

Given genesis config and the commands from the CLI, it starts a full node or a sequencer node.

Please refer to the repository's general README.md file for more instructions and details.
