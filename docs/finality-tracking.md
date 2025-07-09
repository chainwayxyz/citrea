# Full Node Finality Tracking 
(reference other docs!!!)

Citrea full nodes process L1 blocks to extract and verify sequencer commitments and batch proofs, which determine L2 finality.

A sequence of continuous sequencer commitments up to an L2 block height marks that height as "committed". If there are valid batch proofs covering every sequencer commitment in that chain, the final L2 block in that sequence is marked as "proven".

L2 block finality is defined relative to a given L1 block height: at the end of each L1 block, a specific L2 block is considered committed, and a specific L2 block is considered proven.

## Processing L1 blocks

For each finalized L1 block, the full node uses the Bitcoin DA service to extract batch proofs and sequencer commitments. They are processed in the following order:

1. **Processing sequencer commitments**     
    Sequencer commitments are processed according to their transaction index within the L1 block. For each commitment:
    
	- If a commitment with the same index already exists, it is discarded.
	- If the commitment’s L2 range does not advance the committed height, it is discarded.
	- The L2 start height is determined from the previous sequencer commitment. If the previous commitment is missing, the current one is stored as pending.
	- If the full node is not yet synced up to the end of the commitment’s L2 range, the commitment is stored as pending.
	- The Merkle root is verified by reconstructing it from the L2 block hashes; if it does not match, L1 block processing is halted.
	- If all checks pass, the commitment is stored, and the committed L2 height is advanced for the L1 block being processed

2. **Processing batch proofs**  
    For each proof:    

    - Batch proof output is extracted, and the proof is verified against the correct fork's code commitment. If verification fails, proof is skipped.
    - If the last l1 hash on the Bitcoin Light Client is not known by the full node, proof is skipped.
    - If the proof does not advance the proven height, it is discarded.
    - If all any of the commitments referenced by the proof is currently pending, proof is stored as pending as well.
    - If any of the commitments referenced by the proof is not known by the Full node, or the hashes are not matching, proof is skipped.
    - If there are unproven commitments before the beginning of the range of the proof, proof is stored as pending.
    - If all checks pass, the proof is stored, and the proven L2 height is advanced for the L1 block being processed 

3. Processing pending commitments

Pending sequencer commitments, either due to missing previous commitment, or due to L2 blocks it commits were not synced yet, are attempted to be processed. Pending commitments are processed in order by index, since each commitment must build on the previous one.

4. Processing pending proofs

Proofs with missing dependencies, such as L2 range not synced, or one of the commitments it refers to was not processed are attempted to be processed. Pending proofs are processed in order by their commitment index range.

## Querying committed and finalized blocks

L2 finality per the last processed L1 block can queried from the Full node with the following RPC endpoints:

- `citrea_getLastCommittedL2Height`
    Returns the last l2 height that has been committed and the corresponding sequencer commitment index
- `citrea_getLastProvenL2Height`
    Returns the last L2 height that has been proven, along with the corresponding sequencer commitment index that was proven.
- `citrea_getL2StatusHeightsByL1Height`
    Given a certain L1 height, returns the committed and finalized L2 heights and corresponding sequencer commitment indices.

You can also use `Safe` and `Finalized` tags when using Ethereum RPC methods that accept block id or tag. `Safe` tag refers to the last committed L2 block and `Finalized` refers to the last proven L2 block.
Examples endpoints include, `eth_getBlockByNumber`, `eth_getBlockReceipts`, `eth_getBalance` and more. 
