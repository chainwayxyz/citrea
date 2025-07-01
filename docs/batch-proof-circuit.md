# The Batch Proof Circuit

This document describes the logic and structure of batch proof circuits, which generate zero-knowledge proofs to demonstrate that L2 state transitions are correct. The batch proof circuit processes L2 blocks and their transactions to validate state transitions, then submits the proof to the DA layer (Bitcoin). The circuit operates on logical groupings of L2 blocks called sequencer commitments, which serve as a mechanism for organizing and verifying batches of blocks together.

The batch proof circuit's main use case is to provide cryptographic proof that the L2 state transitions are valid and consistent with the sequencer's commitments. These proofs are then used by the light client circuit to verify the overall chain state and provide the L2 state root to Citrea's Bitcoin Bridge, [Clementine](https://citrea.xyz/clementine_whitepaper.pdf).

## Batch Proof Circuit Input

The guest code reads the input from the host in two parts to optimize memory usage and prevent out-of-memory errors in the ZKVM:

### Part 1: Header Information
The first part contains metadata and configuration for the batch proof:

* **Initial state root**: The state root before processing the first sequencer commitment
* **Previous sequencer commitment**: The commitment that precedes the first commitment in the batch (None for the first batch proof)
* **Previous hash proof**: A merkle proof for the last header in the previous sequencer commitment, used to verify the `prev_hash` field of the first block
* **Sequencer commitments**: The list of commitments being proven in this batch
* **Short header proofs**: Proofs for verifying system transactions that update L1 state
* **Cache prune L2 heights**: Heights at which the guest should prune log caches to avoid memory issues
* **Last L1 hash witness**: Witness needed to access the last L1 hash on the Bitcoin Light Client contract

### Part 2: Block Data
The second part is read element by element to avoid loading all witnesses at once:

* **Group count**: Number of sequencer commitment groups
* **For each group**: Number of L2 blocks and their corresponding state/offchain witnesses
* **Each block**: Height, L2 block data, state witness, and offchain witness

This two-part structure ensures that the circuit can process large batches without exceeding memory limits, as witnesses can grow quite large for complex state transitions.

## Circuit Preprocessing

Before processing the sequencer commitments, the circuit performs several validation steps:

1. **Short Header Proof Provider Setup**: Initializes the provider with the short header proofs from the input to verify system transactions
2. **Sequencer Commitment Validation**: Ensures commitments are sequential and properly indexed
3. **Previous Commitment Verification**: If a previous commitment exists, validates the `prev_hash_proof` using merkle proofs to ensure continuity
4. **Fork Management**: Determines the appropriate fork specification based on L2 block heights

## Sequencer Commitment Processing

The main processing loop iterates through each sequencer commitment and applies the contained L2 blocks:

### Commitment Validation
For each sequencer commitment:
* Verifies that commitments are sequential (no gaps in indices)
* Ensures the commitment's L2 end block number matches the expected height
* Validates that the group count matches the number of sequencer commitments

### L2 Block Processing
For each L2 block within a commitment:

1. **Block Validation**: 
   * Verifies the block height matches the expected sequence
   * Checks that the `prev_hash` field matches the hash of the previous block
   * Validates the block signature using the sequencer's public key

2. **State Transition Application**:
   * Applies the L2 block using `StfBlueprint::apply_l2_block`
   * Processes all transactions within the block
   * Updates the state root and accumulates state differences

3. **Merkle Root Verification**:
   * Calculates the merkle root of all L2 block hashes in the commitment
   * Verifies it matches the commitment's claimed merkle root

4. **Cache Management**:
   * Maintains cumulative state and offchain logs for witness optimization
   * Prunes cache logs at specified heights to prevent memory overflow

## Storage Witness System

The batch proof circuit uses a sophisticated storage witness system to efficiently handle state access:

### Witness Structure
A witness contains storage key-value pairs and their corresponding JellyFish Merkle Tree (JMT) proofs. On the native side, the system reads from storage (RocksDB) and generates JMT proofs for key-value pairs, collecting them into the witness. In the ZK environment, this witness serves as the storage layer.

### Cache Optimization
The circuit maintains cumulative state and offchain logs to optimize witness usage:
* If a storage key is accessed in a previous block within the same circuit run, the system reuses the existing proof
* Changes to storage keys are tracked in the cache to avoid regenerating merkle proofs
* Cache pruning occurs at predetermined heights to prevent memory issues

### Witness Verification
In the ZK environment, whenever a storage key-value is read from the witness:
* The corresponding JMT proof is also read and verified
* This ensures the ZK circuit can access storage key-values and prove they are correct
* Prevents malicious input by verifying the integrity of all storage accesses

## Short Header Proof Verification

The circuit uses short header proofs to verify system transactions that update L1 state information:

### Purpose
Short header proofs verify that system transactions calling the Bitcoin Light Client contract are using valid L1 block information. This ensures that the L2 state remains consistent with the L1 state.

### Verification Process
For each system transaction that calls `setBlockInfo`:
* The short header proof provider verifies the L1 block hash, transaction commitment, and coinbase depth
* Ensures the provided parameters match the actual L1 block data
* Tracks verified L1 hashes for output generation

### Provider Implementation
The circuit uses `ZkShortHeaderProofProviderService` which:
* Maintains a queue of short header proofs from the input
* Verifies each proof against the system transaction parameters
* Tracks the last queried hash for output generation

## L1 Hash Verification

After processing all sequencer commitments, the circuit verifies the last L1 hash stored in the Bitcoin Light Client contract:

### Verification Logic
The circuit checks if any L1 hashes were verified during processing:
* If short header proofs were used, the last queried hash is used
* Otherwise, the circuit reads the last L1 hash from the Bitcoin Light Client contract storage using the provided witness

### Storage Access
The L1 hash is stored in the EVM storage of the Bitcoin Light Client contract:
* First reads the next L1 height from storage slot 0
* Calculates the storage slot for the last L1 hash using keccak256
* Reads the hash value using the provided witness and verifies the JMT proof

### Output Generation
The verified L1 hash is included in the circuit output so that the light client circuit can verify that the batch proof is consistent with the latest L1 state.

## Batch Proof Circuit Output

After successfully processing all sequencer commitments, the circuit outputs:

* **State roots**: All state roots from initial state through the final state root of the batch proof
* **Final L2 block hash**: Hash of the last L2 block processed
* **State diff**: Cumulative state differences from all processed L2 blocks
* **Last L2 height**: The highest L2 block height processed
* **Sequencer commitment hashes**: Hashes of all processed sequencer commitments
* **Sequencer commitment index range**: The range of commitment indices processed
* **Last L1 hash on Bitcoin Light Client contract**: The verified L1 hash for light client verification
* **Previous commitment index and hash**: Information for linking with previous batch proofs

## Error Handling and Validation

The circuit performs extensive validation and panics on any failure to ensure proof integrity:

* **Sequential commitment validation**: Ensures no gaps in commitment indices
* **Block height verification**: Confirms each block has the expected height
* **Previous hash verification**: Validates block chain continuity
* **Merkle root verification**: Ensures commitment integrity
* **State root consistency**: Verifies state transitions are correct
* **Signature validation**: Confirms blocks are properly signed by the sequencer

## Integration with Light Client Circuit

The batch proof circuit is designed to work seamlessly with the light client circuit:

* **Stateless design**: Each batch proof is independent and doesn't depend on previous proofs
* **Linking information**: Output includes previous commitment details for light client linking
* **L1 hash verification**: Provides verified L1 state for light client validation
* **Method ID tracking**: Uses method IDs to ensure proof authenticity across different circuit versions

The light client circuit uses the batch proof outputs to verify that the entire chain is propagating correctly and to provide the final L2 state root to the bridge contract.
