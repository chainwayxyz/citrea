# Citrea Bridge Contract (`Bridge.sol`)

This document provides an overview of the `Bridge.sol` smart contract, which is the core part of the Citrea-Bitcoin bridge in the Citrea side. It facilitates the transfer of BTC between the Bitcoin network and the Citrea rollup.

## Overview

`Bridge.sol` is a smart contract deployed on Citrea. Its two primary functions are handling deposits and withdrawals. For deposits, it verifies that BTC has been locked on the Bitcoin network before minting the corresponding cBTC on Citrea. For withdrawals, it locks cBTC and stores the information required for the user to withdraw BTC on the Bitcoin network.


The bridge is designed to be trust-minimized and secure, check [Clementine whitepaper](https://citrea.xyz/clementine_whitepaper.pdf) for further information about the Bridge in general.

## Core Concepts

### Bitcoin Light Client Integration

The bridge relies on the `BitcoinLightClient` smart contract to verify that a given Bitcoin transaction has been included in a block and is part of the canonical Bitcoin chain using Simple Payment Verification (SPV). It validates Merkle proofs submitted with deposit transactions.

### Roles

-   **Owner**: The contract owner, who has administrative privileges. The owner can update critical parameters like the operator address and the deposit script format.
-   **Operator**: A privileged address, responsible for relaying valid deposit transactions from Bitcoin to the bridge contract. (The Operator in the bridge contract should not be confused with the Operators on the Clementine bridge design that are responsible for withdrawals.)
-   **System Caller**: A special, hardcoded address (`0xdeaD...`) used for initializing the contract and other system-level functions.

## Deposit Flow: Bitcoin to Citrea

The process of moving BTC from Bitcoin to Citrea involves actions on both chains.

1.  **Bitcoin Transaction**: A user sends (`depositAmount`) of BTC with the deposit transaction. This transaction has two spending paths: first one is the N-of-N multisig, and the second one is the user gets back after 200 blocks. This timeout exists to prevent users from losing their BTC if the required signatures for the Clementine bridge couldn't be collected. After the signers of the N-of-N multisig accepts this deposit, they send the moveTx. This is the transaction that we prove it's inclusion on the Bitcoin through the `BitcoinLightClient`.
2.  **Witness Data**: The `moveTx` is constructed with a specific witness. This witness includes:
    -   A script that contains the recipient's Citrea address (a 20-byte address).
    -   A predefined `depositPrefix` and `depositSuffix` within the script.
    -   A Schnorr signature from the N-of-N.
3.  **Relaying to Citrea**: Once the move transaction is confirmed, the deposit is relayed to the sequencer which has a separate pool for the deposit transactions. Then a system transaction calling the `deposit()` function on `Bridge.sol` is created and put into a block by the sequencer. The system transactions are free, so deposits don't require any existing funds on Citrea for the depositor.
4.  **On-Chain Verification**: The `deposit()` function executes a series of critical checks:
    -   **Inclusion Proof**: It uses the `BitcoinLightClient` to validate the provided Merkle proof, ensuring the transaction is final on Bitcoin.
    -   **Signature Verification**: It reconstructs the BIP-341 Taproot sighash and calls the precompile at `0x200` to verify the operators' Schnorr signature. This confirms the transaction's authenticity.
    -   **Script Validation**: It parses the witness script to confirm it matches the required format (`depositPrefix` + `recipient_address` + `depositSuffix`).
    -   **Replay Protection**: It records the Bitcoin transaction ID (`txId`) and ensures it cannot be used for a deposit more than once.
5.  **Minting cBTC**: The bridge contract is funded with 21M CBTC at the genesis. If all validations pass, the contract extracts the recipient's address from the script and sends `depositAmount` of cBTC on Citrea to their account. If the transfer fails, the funds are sent to a `failedDepositVault`.

## Withdrawal Flow: Citrea to Bitcoin

The withdrawal process moves assets from Citrea back to Bitcoin.

1.  **Initiate Withdrawal**: A user wanting to withdraw from Citrea, first acquires a dust output (financially irrelevant, or even 0 sat) on Bitcoin. Then they call the `withdraw()` or `batchWithdraw()` function on the bridge contract with `depositAmount` (essentially burning/locking their balance) and with this dust UTXO. 
2.  **Request Queue**: The contract records this request in a public `withdrawalUTXOs` array. This array serves as a queue of pending withdrawals for the operators to process.
3.  **Completion of the Withdrawal**: After calling the `withdraw()` function, the user signs a `SIGHASH_ALL | ANYONECAN_PAY` PSBT that spends this dust UTXO and outputs `depositAmount` to an address they control. The user then starts an off-chain dutch auction in which they decrease the amount they receive on the Bitcoin side via publishing new signatures when no bridge operator accepts the signed PSBT. When an operator accepts the PSBT, they add the necessary outputs to the PSBT and broadcast the transaction.
4.  **`safeWithdraw()`**: The contract also provides a `safeWithdraw` function. This method offers users greater security by doing extra security checks such as verifying the user's signature, and the transaction's inclusion.
