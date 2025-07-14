# Differences of Citrea EVM Implementation
Even though Citrea uses a fully Ethereum mainnet compatible EVM executor ([revm](https://crates.io/crates/revm)), there are certain parts where Citrea differs from Ethereum mainnet.

Currently, Citrea is on Prague spec with following differences:

## Precompiles

### No Point Evaluation Precompile
Due to the costs of KZG verification in ZK circuits, this precompile was removed. The address `0x0A` behaves like an EOA on `calls`.

### Schnorr Verify Precompile
Under `crates/evm/src/evm/precompiles` the schnorr verifier precompile can be found. This precompile is used in Citrea's canonical bridge operations, however, the precompile is open for calls from any other smart contract.

The precompile lives at `0x0000000000000000000000000000000000000200`.

### `secp256r1` Precompile
Citrea implements [RIP-7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md).

## System Contracts

### No EIP-2935 & EIP-7002
These EIPs are not implemented in Citrea.

### Citrea Specific System Contracts

| Address                                      | Name & Link                                                                 |
|----------------------------------------------|------------------------------------------------------------------------------|
| `0x3100000000000000000000000000000000000001` | [Bitcoin Light Client Proxy](https://explorer.testnet.citrea.xyz/address/0x3100000000000000000000000000000000000001) |
| `0x3100000000000000000000000000000000000002` | [Bridge Proxy](https://explorer.testnet.citrea.xyz/address/0x3100000000000000000000000000000000000002) |
| `0x3100000000000000000000000000000000000003` | [Base Fee Vault Proxy](https://explorer.testnet.citrea.xyz/address/0x3100000000000000000000000000000000000003) |
| `0x3100000000000000000000000000000000000004` | [L1 Fee Vault Proxy](https://explorer.testnet.citrea.xyz/address/0x3100000000000000000000000000000000000004) |
| `0x3100000000000000000000000000000000000005` | [Priority Fee Vault Proxy](https://explorer.testnet.citrea.xyz/address/0x3100000000000000000000000000000000000005) |
| `0x3100000000000000000000000000000000000006` | [WCBTC](https://explorer.testnet.citrea.xyz/address/0x3100000000000000000000000000000000000006) |
| `0x3200000000000000000000000000000000000001` | [Bitcoin Light Client Implementation](https://explorer.testnet.citrea.xyz/address/0x3200000000000000000000000000000000000001) |
| `0x3200000000000000000000000000000000000002` | [Bridge Implementation](https://explorer.testnet.citrea.xyz/address/0x3200000000000000000000000000000000000002) |
| `0x3200000000000000000000000000000000000003` | [Base Fee Vault Implementation](https://explorer.testnet.citrea.xyz/address/0x3200000000000000000000000000000000000003) |
| `0x3200000000000000000000000000000000000004` | [L1 Fee Vault Implementation](https://explorer.testnet.citrea.xyz/address/0x3200000000000000000000000000000000000004) |
| `0x3200000000000000000000000000000000000005` | [Priority Fee Vault Implementation](https://explorer.testnet.citrea.xyz/address/0x3200000000000000000000000000000000000005) |
| `0x31ffffffffffffffffffffffffffffffffffffff` | [Proxy Admin](https://explorer.testnet.citrea.xyz/address/0x31ffffffffffffffffffffffffffffffffffffff) |0x31ffffffffffffffffffffffffffffffffffffff

Source code and genesis creation scripts can be found under `crates/evm/src/evm/system_contracts`.

For more information on the Bitcoin Light Client Contract and  Bridge Contract, see [bitcoin-light-client-contract.md](bitcoin-light-client-contract.md) and [bridge-contract.md](./bridge-contract.md).


## Blocks, Fees & Transactions

### Gas limit
Citrea blocks have 10 million gas limit, except for tests where we have different amount of gas set in different tests.

### Block times
Citrea blocks are produced every 2 seconds. The timing of the blocks are controlled by the sequencer and are not guaranteed to meet the 2 second interval.

### Block base fee
Though Citrea implements EIP-1559, the base fee of Citrea blocks have a lower limit of `0.01 Gwei`.

### L1 Fees
Citrea posts ZK proofs of block range executions on Bitcoin. These proofs output the state difference of the rollup between the block range. Therefore, the rollup charges transactions an L1 fee based on the its "diff size".

As the diffs are batched and there is no way to know how many times a storage slot or account will change values at the time of the transaction execution, a statistical discount is applied on the diff sizes in order not to overcharge the transactions.

Code related to the L1 fees can be found in `crates/evm/src/evm/handler.rs`

### No EIP-4844
EIP-4844 transaction cannot be included in L2 blocks. `BLOBBASEFEE` always returns 1.

### System Transactions
System transactions are transactions that are done by the system signer `0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD`. These transactions are put inside the L2 blocks by the sequencer and they are not charged any fees.

Currently, there are 4 types of system transactions.

- **Bitcoin Light Client Contract Initialize**: Initializes the Bitcoin Light Client Contract by setting the first height and hash for the L1.
- **Bitcoin Light Client Set Block Info**: Sets the hash and other related information for the next L1 height.
- **Bridge Initialize**: Initializes the Bridge Contract.
- **Bridge Deposit**: Handles deposits made to Citrea, as this is handled by system transactions, bridging to Citrea is free.

## JMT Storage Tree
In order to have more efficient ZK proving, the Citrea rollup uses [Jellyfish Merkle Trie](https://github.com/penumbra-zone/jmt) instead of the Merkle-Patricia Trie used by Ethereum and some of its L2s.

The storage layout for addresses and storage slots are also different. Further detail of the layout can be obtained by examining the `crates/evm/src/lib.rs` file.

As so `EIP1186AccountProofResponse` should be handled differently then Ethereum proofs, however, the RPC request and responses uses the same layout. `generate_eth_proof` function in `crates/evm/src/rpc_helpers/mod.rs` handles generation for these proofs.