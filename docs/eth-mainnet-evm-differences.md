# Differences of Citrea EVM Implementation
Even though Citrea uses a fully Ethereum mainnet compatible EVM executor ([revm](https://crates.io/crates/revm)), there are certain parts where Citrea differs from Ethereum mainnet.

Currently, Citrea is on Prague spec with following differences:

## Precompiles


### Lack of point evaluation precompile
Due to the costs of KZG verification in ZK circuits, this precompile was removed. The address `0x0A` behaves like an EOA on `calls`.

### Additional Schnorr verify precompile
Under `crates/evm/src/evm/precompiles` the schnorr verifier precompile can be found. This precompile is used in Citrea's canonical bridge operations, however, the precompile is open for calls from any other smart contract.

The precompile lives at `0x0200`

### Additional `secp256r1` precompile
Citrea implements [RIP-7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md).

## Blocks & Fees

### Gas limit
Citrea blocks have 10 million gas limit.

### Block times
Citrea blocks are produced every 2 seconds. The timing of the blocks are controlled by the sequencer and are not guaranteed to meet the 2 second interval.

### Block base fee
The base fee of Citrea blocks have a lower limit of `0.01 Gwei`

### L1 Fees
Citrea posts ZK proofs of block range executions on Bitcoin. These proofs output the state difference of the rollup between the block range. Therefore, the rollup charges transactions an L1 fee based on the its "diff size".

As the diffs are batched and there is no way to know how many times a storage slot or account will change values at the time of the transaction execution, a statistical discount is applied on the diff sizes in order not to overcharge the transactions.

Code related to the L1 fees can be found in `crates/evm/src/evm/handler.rs`

