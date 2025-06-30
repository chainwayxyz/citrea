# The Light Client Circuit
This document describes the logic and structure of light client proofs, which allow a verifier to confirm that an L2 state committed to by the sequencer is valid, using information included in a DA (Data Availability) block. Each proof builds on the previous one, forming a verifiable chain of state transitions. Verifying a single proof attests that, for the given Bitcoin chain up to that DA block, the L2 state produced by the circuit is correct, verified, and consistent with the on-chain commitments.

## Light Client Circuit Input

The guest code reads the input from the host. It contains data about the DA block being processed:

* **Inclusion proof**: Contains `wtxids`, coinbase transaction to verify the witness merkle root, and a merkle proof for the inclusion of the coinbase transaction.  
* **Completeness proof**: A vector of the relevant transactions. Transactions are considered relevant if their wtxid begins with a predefined constant reveal transaction prefix.  
* **Block header**: Header of the block that is being processed

The input also includes:

* **Previous light client proof**: Proof of the previous L1 block. This is None for the first proof, but must be present for all subsequent proofs.  
* **Light client proof method ID**: Used to verify the previous light client proof. Once supplied, it is passed unchanged to the proof output and cannot be modified afterward.  
* **Witness**: Used for accessing the light client’s JellyFish Merkle Tree (JMT) state

The guest program matches the Citrea network with the corresponding constants and calls the `LightClientProofCircuit::run_circuit` with them and the circuit input.

## Circuit Preprocessing

Before processing the L1 block logic, the circuit:

1. Verifies the previous light client proof and extracts its output.  
2. Uses `DaVerifier::verify_header_chain` to check if the new block header is valid under the Bitcoin consensus rules (including proof-of-work) and follows the latest DA block from the previous light client proof. If there is no previous light client proof, a predefined constant initial network state is used.  
3. Uses `DaVerifier::verify_transactions` to validate the inclusion and completeness proofs against the block header and retrieve the relevant transactions from the DA block. This guarantees that all relevant transactions in the DA block will be processed.

## L1 Block Processing

`LightClientProofCircuit::run_l1_block` is called with:

* The DA header  
* Relevant transactions  
* Previous light client proof  
* Constants from the guest main

This function processes the relevant transactions, moves the light client state forward, and validates the changes to the LCP’s JMT state. Before processing the transactions:

* The block hash of the header is inserted into the JMT.  
* The last sequencer commitment index, last L2 height, and L2 state root are retrieved from the previous light client proof.  
* If no previous proof exists, (0, 0, genesis root) is used as the starting point, and the initial method IDs are set. Both the genesis root and the initial method IDs are predefined constants, committed through the light client proof method ID.

## Processing the Relevant Transactions

* **Complete batch proof**: After checking that the sender is the batch prover, the proof is processed with `LightClientProofCircuit::process_complete_proof`. If any error is returned, proof is skipped.  
    
* **Chunk proof**: Stored in JMT to construct the complete proof body later.  
    
* **Aggregate proof**: Contains `wtxids` to construct the complete proof. After verifying that the sender is the batch prover, the chunk bodies are retrieved from the JMT by their `wtxid`s and assembled into a complete proof, which is processed using the same method as before.  
    
* **Batch proof method ID**: Contains the method ID and the activation (L2) height. If the sender is the method ID upgrade authority and the activation height is higher than the latest one, the new method ID is stored in the JMT for use in future proof verification.  
    
* **Sequencer commitment**: If submitted by the sequencer and no existing commitment is stored for that index, it is added to the JMT state.

### Processing Complete Proofs

Before validating the proof and its output, it is decompressed. Decompression may fail if the decompressed blob size limit is exceeded or if there is invalid data. If decompression fails, the proof is skipped.

After that, the following checks are performed:

* Whether the last L1 hash on the Bitcoin light client contract was seen by the LCP.  
* If the proof is valid. It is verified using the method IDs on the LCP’s JMT state.  
* If the sequencer commitment relation holds.

If any of these fail, an error is returned. On successful verification, for every sequencer commitment in the batch proof’s range, the L2 state update is marked as `VerifiedStateTransition` in the JMT state for that commitment. This marking is later used when advancing the L2 state of the LCP.

#### Verifying the Sequencer Commitment Relation

Since the batch prover circuit commits to the sequencer commitment indices and hashes (including the previous commitment), these can be compared against the commitments stored in the LCP’s JMT state. Proofs are only accepted if all referenced commitments are recognized and match.

1. First, it is checked if the previous commitment on the batch proof matches the commitment on the JMT state. This way, LCP can verify that the proof was built over a valid sequencer commitment and cannot be tricked into an invalid L2 state.  
     
2. Next, the sequencer commitments within the batch proof range are iterated over. For any commitment:  
     
   * The commitment index must exist in the JMT state.  
   * The commitment hash must match the corresponding hash stored in the JMT state.  
   * For the final commitment in the range, it is verified that the batch proof’s last L2 height matches the L2 height of the corresponding commitment stored in the JMT state.

## Moving the Verified Commitment Index

To advance the L2 state, the JMT is checked for a verified state transition following the last confirmed sequencer commitment. If the transition’s initial state root matches the last L2 state root of the light client proof, the following are updated:

* The last L2 height  
* Last L2 state root  
* The sequencer commitment index

## Verifying the JMT Update

As the final step, `ZkStorage::compute_state_update` is used to verify both the reads from and the updates to the JMT storage, based on the read and update proofs included in the witness. It is then asserted that the state transition’s initial root matches the final JMT state root from the previous light client proof.

## Light Client Proof Output

After running the L1 block logic of the circuit, the circuit outputs the verified L2 state as of the processed DA block, consisting of:

* L2 state root  
* Last L2 height  
* Last sequencer commitment index

For the next light client proof, it also provides:

* Latest DA state  
* Light client method ID  
* JMT state root
