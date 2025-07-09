# Light Client Proof, Citrea, and the Clementine Bridge

> **Before reading this document**, it is highly recommended to review the [Clementine Whitepaper](https://citrea.xyz/clementine_whitepaper.pdf) and other relevant Citrea documentation. This document assumes a comprehensive understanding of the system and builds on concepts discussed elsewhere.

Citrea uses the **Clementine bridge** to treat BTC as a native asset. This bridge enables:

- **Depositing BTC** → to receive **cBTC** in Citrea (Peg-In)
- **Withdrawing BTC** → by **burning cBTC** in Citrea (Peg-Out)

---

## Peg-In: Deposit Process

1. **Deposit Transaction**  
   The user initiates a Bitcoin transaction locking, e.g., 10 BTC. The UTXO created:
   - Can be reclaimed by the user after `t1` blocks, **or**
   - Can be spent by revealing the depositor’s **Citrea address** (via a covenant).

   Since Bitcoin does not yet support covenants, the depositor shares their Citrea address with the bridge **signers**, who then **pre-sign a MoveToVault transaction**.  
   This transaction transfers the BTC to a vault UTXO and reveals the depositor’s Citrea address on-chain. The vault output is structured such that it can be redeemed in the Peg-Out phase by the **Operator**.

2. **MoveToVault Submission & Light Client Interaction**  
   When the MoveToVault transaction is posted on Bitcoin, it reveals the recipient’s Citrea address.  
   Citrea runs a system contract called [**Bitcoin light client**](./bitcoin-light-client-contract.md), which will be used to verify this transaction’s inclusion.

3. **System Transaction Generation via RPC**  
   Clementine’s aggregator sends the deposit data to the Citrea Sequencer using the RPC call:
   `citrea_sendRawDepositTransaction`
    This generates a **Citrea system transaction** calling the [`deposit`](./bridge-contract.md) function of the Bridge Contract with:
    - The `MoveToVault` transaction
    - Merkle proof of its Bitcoin inclusion (verified via the [`verifyInclusion`](crates/evm/src/evm/system_contracts/src/BitcoinLightClient.sol) function  of the Light Client Contract)
    - SHA script pubkeys (for verifying Schnorr signatures in the MoveTx)

4. **Finalization**  
    Inside the `deposit` function:
    - In the deposit function firstly witness is extracted, from witness,  the script and from the script the recipient address (depositor Citrea address) is extracted.
    - If validations are successful the **cBTC is minted** to the recipient’s Citrea account.

---

## Peg-Out: Withdrawal Process

When the user wants to exit Citrea:

1. The user sends a **Burn transaction**, burning their 10 cBTC on Citrea.
    a. Burning has to be done against the bridge contract, not all burning works(like sending funds to 0x0...000 will not be the same)
2. The rollup includes this transaction in a future block.
3. Once Citrea finalizes and checkpoints the block on Bitcoin in a batch proof, the user can withdraw the original BTC.

For a deeper dive into this flow, refer to the [Bridge Contract documentation](./bridge-contract.md).

---

## The Bridge Circuit in Clementine

The **Bridge Circuit** within Clementine handles proof validation for both deposits and withdrawals using the Citrea Light Client Proof (LCP). Here's how it works:

1. **Proof Generation**
- The **Citrea Light Client Prover** scans [Batch Proofs](./batch-proof-circuit.md), which contain ZK-proofs of L2 state transitions.
- For every Bitcoin block, the prover generates an **LCP** that attests to the latest Citrea state root.

2. **Proof Verification**
- The Clementine **Bridge Circuit** consumes these LCPs.
- Verification is performed using the **RISC0** API.
- If valid, the **L2 state root** is extracted from the proof output.

3. **Storage Proof Preparation**
- The MoveToVault transaction carries payout info (e.g., the bitcoin block height and deposit index).
- The Operator uses this data to:
  - Request the **Light Client Proof** for that block with that block height from Citrea.
  - Extract the corresponding **L2 height** from it.
  - Derive **storage keys** needed to prove:
    - The UTXO
    - The `vout`
    - The deposit slot
  - These keys, along with the L2 height, are used in an `eth_getProof` RPC call to Citrea to retrieve the **storage proofs**.

4. **Bridge Circuit Execution**
- The storage proofs are converted to [`EIP1186StorageProof`](https://eips.ethereum.org/EIPS/eip-1186) format.
- The Bridge Circuit verifies their inclusion using Merkle proofs.
- This storage proof verifies that there was in fact a withdrawal
