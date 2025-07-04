# Sequencer Commitment

A **sequencer commitment** is a logical grouping of L2 blocks that serves as a unit of batching and verification in Citrea's rollup architecture. Sequencer commitments are published to the Data Availability (DA) layer (Bitcoin) and are used by the batch proof circuit to organize and prove the correctness of L2 state transitions.

## Structure
A sequencer commitment contains:
- **Merkle root**: The root of a Merkle tree built from the hashes of all L2 blocks included in the commitment.
- **Index**: A unique, sequential index for the commitment (starting from 1).
- **L2 end block number**: The height of the last L2 block included in this commitment.

**Note**: The L2 start block number is not explicitly stored in the commitment structure because it can be calculated deterministically from the previous commitment's end block number.

## L2 Start Block Number Calculation

The L2 start block number for a sequencer commitment is calculated as follows:

- **For subsequent commitments**: `previous_commitment.l2_end_block_number + 1`
- **For the first commitment (index 1)**: Depends on the network and fork configuration

### First Commitment L2 Start Height

The first commitment's L2 start height varies by network:

- **Newly started chains**: L2 start height is 1
- **Existing chains**: L2 start height is the Tangerine fork activation height

The Tangerine fork activation height is determined by the network's fork configuration:
- **Mainnet**: Tangerine activates at height 0, first commitment starts at height 1
- **Testnet**: Tangerine activates at height 9,057,000, first commitment starts at height 9,057,000
- **Devnet**: Tangerine activates at height 0, first commitment starts at height 1
- **Nightly/Testing**: Uses the latest fork specification

This design ensures that the first batch proof starts from the appropriate L2 height based on the network's state and fork progression.

## Purpose and Role
- **Batching**: Sequencer commitments allow the sequencer to group multiple L2 blocks together for efficient proof generation and submission to the DA layer.
- **Verification**: The batch proof circuit verifies that all L2 blocks in a commitment are valid and that their hashes match the claimed Merkle root.
- **Chain Linking**: Commitments are indexed sequentially, and the batch proof circuit ensures there are no gaps or overlaps between commitments. This enables the light client circuit to verify the continuity and validity of the L2 chain.

## In the Batch Proof Circuit
- The batch proof circuit receives a list of sequencer commitments as input and processes the L2 blocks within each commitment.
- The circuit calculates the L2 start height for each commitment using the deterministic formula.
- The circuit checks that the commitments are sequential and that the Merkle roots are correct.
- The output of the batch proof circuit includes the hashes and index range of the processed commitments, which are then used by the light client circuit for further verification.

Sequencer commitments are a foundational concept for ensuring the integrity and verifiability of L2 state transitions in Citrea. 