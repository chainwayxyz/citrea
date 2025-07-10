# Full Node Finality Tracking

Citrea Full nodes process L1 blocks to extract and verify [sequencer commitments](./sequencer-commitment.md) and [batch proofs](./batch-proof-circuit.md), which determine L2 finality.

A sequence of continuous sequencer commitments up to an L2 block height marks that height as "committed". If there are valid batch proofs covering every sequencer commitment in that chain, the final L2 block in that sequence is marked as "proven".

L2 block finality is defined relative to each L1 block height: at the end of an L1 block, a specific L2 block is marked as committed and another as proven. The committed height is always less than or equal to the proven height.

The Full nodes imitate how the [Light Client Proof](./light-client-circuit.md) tracks the latest state of the rollup. As of now, there are minor differences between the two, and these are tracked on [#2212](https://github.com/chainwayxyz/citrea/issues/2212).
## Processing L1 blocks

For each finalized L1 block, the full node uses the Bitcoin DA service to extract batch proofs and sequencer commitments. They are processed in the following order:

1. **Processing sequencer commitments**  
   Sequencer commitments are processed according to their transaction index within the L1 block. For each commitment:  
     
   - If a commitment with the same index already exists, it is discarded.  
   - If the commitment’s L2 range does not advance the committed height, it is discarded.  
   - The L2 start height is determined from the previous sequencer commitment. If the previous commitment is missing, the current one is stored as pending.  
   - If the full node is not yet synced up to the end of the commitment’s L2 range, the commitment is stored as pending.  
   - The Merkle root is verified by reconstructing it from the L2 block hashes; if it does not match, L1 block processing is halted.  
   - If all checks pass, the commitment is stored, and the committed L2 height is advanced for the L1 block being processed.

2. **Processing batch proofs**  
   For each proof:  
     
   - The batch proof output is extracted, and the proof is verified against the correct fork's code commitment. If verification fails, proof is skipped.  
   - If the full node does not know the last L1 hash on the [Bitcoin Light Client](./bitcoin-light-client-contract.md), proof is skipped.  
   - If the proof does not advance the proven height, it is discarded.  
   - If any of the sequencer commitments referenced by the proof are pending, the proof is stored as pending.

   - If any referenced commitments are unknown to the full node or their hashes do not match, the proof is skipped.

   - If there are unproven commitments before the proof’s L2 range, the proof is stored as pending.

   - If all checks pass, the proof is stored, and the proven L2 height is advanced for the L1 block being processed.  
3. **Processing pending commitments**

Sequencer commitments that are pending due to missing previous commitments or unsynced L2 blocks are processed again in order. They are processed in order by index, since each commitment must build on the previous one.

4. **Processing pending proofs**

Pending proofs with unresolved dependencies — such as unsynced L2 ranges or unprocessed referenced commitments — are also re-attempted. These proofs are processed in order based on their referenced commitment index range.

## Querying committed and finalized blocks

The full node exposes the following RPC endpoints to query L2 finality based on the last processed L1 block:

- `citrea_getLastCommittedL2Height`     
    Returns the most recent committed L2 height and its corresponding sequencer commitment index.

- `citrea_getLastProvenL2Height`    
    Returns the most recent proven L2 height and the corresponding sequencer commitment index that has been proven.

- `citrea_getL2StatusHeightsByL1Height`     
    Given an L1 block height, returns the committed and proven L2 heights along with their sequencer commitment indices.

Additionally, you can use the `safe` and `finalized` tags when calling Ethereum RPC methods that accept a block ID or tag. The `safe` tag resolves to the last committed L2 block, while `finalized` refers to the last proven L2 block. Example RPC endpoints include `eth_getBlockByNumber`, `eth_getBlockReceipts`, `eth_getBalance`, and more.