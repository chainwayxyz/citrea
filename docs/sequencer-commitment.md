# Sequencer Commitment

A **sequencer commitment** is a logical grouping of L2 blocks that serves as a unit of batching and verification in Citrea's rollup architecture. Sequencer commitments are published to the Data Availability (DA) layer (Bitcoin) and are used by the batch proof circuit to organize and prove the correctness of L2 state transitions.

## Structure
A sequencer commitment typically contains:
- **Merkle root**: The root of a Merkle tree built from the hashes of all L2 blocks included in the commitment.
- **Index**: A unique, sequential index for the commitment (starting from 1).
- **L2 end block number**: The height of the last L2 block included in this commitment.

## Purpose and Role
- **Batching**: Sequencer commitments allow the sequencer to group multiple L2 blocks together for efficient proof generation and submission to the DA layer.
- **Verification**: The batch proof circuit verifies that all L2 blocks in a commitment are valid and that their hashes match the claimed Merkle root.
- **Chain Linking**: Commitments are indexed sequentially, and the batch proof circuit ensures there are no gaps or overlaps between commitments. This enables the light client circuit to verify the continuity and validity of the L2 chain.

## In the Batch Proof Circuit
- The batch proof circuit receives a list of sequencer commitments as input and processes the L2 blocks within each commitment.
- The circuit checks that the commitments are sequential and that the Merkle roots are correct.
- The output of the batch proof circuit includes the hashes and index range of the processed commitments, which are then used by the light client circuit for further verification.

Sequencer commitments are a foundational concept for ensuring the integrity and verifiability of L2 state transitions in Citrea. 