(TOOD: Give general Information About the Purpose of the Light Client Proofs first)

## Light Client Circuit Input

The guest code reads the input from the host. It contains data about the DA block being processed:

* **Inclusion proof**: Contains `wtxids`, coinbase transaction to verify the witness merkle root, and a merkle proof for the inclusion of the coinbase transaction.
* **Completeness proof**: A vector of the relevant transactions.
* **Block header**: Header of the block that is being processed

The input also includes:

* **Previous light client proof**: Proof of the previous L1 block (if it exists)
* **Light client proof method id**: Used to verify the previous light client proof
* **Witness**: Used for accessing light client’s JMT state

The guest program matches the Citrea network with the corresponding constants and calls the `LightClientProofCircuit::run_circuit` with them and the circuit input.

## Circuit Preprocessing

Before processing the L1 block logic, the circuit:

1. Verifies the previous light client proof and extracts its output.
2. Using the `DaVerifier::verify_header_chain`, verifies whether the new block header is valid and the child of the latest DA block associated with the previous light client proof. If the previous LC proof is not present, constant initial network state is used.
3. Using the `DaVerifier::verify_transactions`, verifies the inclusion and completeness proof with the block header and retrieves the relevant transactions in the DA block. This way it is guaranteed that all relevant transactions in the DA block will be processed.


## L1 Block Processing

`LightClientProofCircuit::run_l1_block` is called with:

* The DA header
* Relevant transactions
* Previous light client proof
* Constants from the guest main

This function processes the relevant transactions, moves the light client state forward, and validates the changes to the LCP’s JMT state. Before processing the transactions:

* The block hash of the header is inserted to the JMT.
* Last sequencer commitment index, last L2 height and state root is retrieved from the previous light client proof.
* If this is the first light client proof, (0,0, genesis root) is used above, and the initial method ids are initialized.

## Processing the Relevant Transactions

* **Complete batch proof**:
  After checking that the sender is the batch prover, the proof is processed with `LightClientProofCircuit::process_complete_proof`. If any error is returned, proof is skipped.

* **Chunk proof**:
  Stored in JMT to construct the complete proof body later.

* **Aggregate proof**:
  After checking that the sender is the batch prover, the complete proof is constructed by retrieving the chunk bodies by their `wtxids` from the aggregate data and piecing them together. The complete proof is processed the same way explained before.

* **Batch proof method ID**:
  The data contained is the method id and the activation (L2) height. If the sender is the method id upgrade authority, and the activation height is greater than the latest method id’s activation height. The new method id is inserted into the JMT to be used later in proof verification.

* **Sequencer commitment**:
  If sent by the sequencer and there is no prior commitment saved for that index, inserted into the JMT state.

### Processing Complete Proofs

It is checked:

* Whether the last L1 hash on the bitcoin light client contract was seen by the LCP (#1986).
* If the proof is valid. Verifying using the method IDs on the LCP JMT state.
* If the sequencer commitment relation holds.

If any of these fail, proof is skipped. Next, for every sequencer commitment in the batch proof’s range, L2 state update is marked as `VerifiedStateTransition` that commitment. This is to be used later when we move the L2 state of the LCP.

#### Verifying the Sequencer Commitment Relation

1. First, it is checked if the previous commitment on the batch proof matches the commitment on the JMT state. This way LCP can verify that the proof was built over a valid sequencer commitment and cannot be tricked into an invalid L2 state.

2. Next, we iterate over the sequencer commitments in the batch proof range. For any commitment:

   * The commitment index must exist in the JMT state.
   * The commitment hash must match the corresponding hash stored in the JMT state.
   * For the last commitment, we check if the batch proof’s last L2 height matches the L2 height of the corresponding commitment in the JMT state.

## Moving the Verified Commitment Index

To advance the L2 state, we use the JMT state to verify whether there is a valid state transition following the last sequencer commitment. Once we confirm that the transition’s initial state root matches the last L2 state root of the LCP, we update:

* The last L2 height
* Last L2 state root
* The sequencer commitment index

## Verifying the JMT Update

As the final step, we verify both the reads from and the updates to the JMT storage with the `compute_state_update` method, and assert that the JMT state transition’s initial state root matches the final JMT state root of the previous light client proof output.

## Light Client Proof Output

After running the L1 block logic of the circuit, we produce the proof output.
As of that DA block, we output the verified L2 state as:

* L2 state root
* Last L2 height
* Last sequencer commitment index

To be used in the next light client proof we also output:

* Latest DA state
* Light client method ID
* JMT state root
