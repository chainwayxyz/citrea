## Citrea EVM

This EVM crate is key of Citrea's compatibility with the EVM, while utilizing the logic implemented by the Sovereign SDK. The key features related to this crate are:

- Implementation of EVM logic & methods on top of Sovereign SDK's Module API
  - The way EVM-related parts work, and its implementation on `sov-modules-api` for the Sovereign SDK & rollup to function properly.
- Execution, DB, Account Handlers
  - A separate EVM-DB, account management of the chain and its execution
- The system contract
  - A system contract that keeps track of L1. It will also play an important role for our bridge, [Clementine](https://github.com/chainwayxyz/clementine).
- Tracing methods for transactions
  - Used in Call/Gas simulations for the EVM (compatible with EIP-1559), mostly.
- Extensive EVM tests
  - These tests are independent from [Hive](https://github.com/ethereum/hive) tests of Ethereum Foundation. We maintain them in the `hive` folder.

We -mostly- use the types that are developed for [Reth](https://github.com/paradigmxyz/reth), and update them on a regular basis.

Please feel free to submit a PR/issue in case you encounter a problem regarding any implementation/usage in this crate.
