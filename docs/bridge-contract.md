# Citrea Bridge Contract (`Bridge.sol`)

This document provides an overview of the `Bridge.sol` smart contract, which is the core part of the Citrea-Bitcoin bridge in the Citrea side. It facilitates the transfer of BTC between the Bitcoin network and the Citrea rollup.

## Overview

`Bridge.sol` is a smart contract deployed on the Citrea. Its two primary functions are handling deposits and withdrawals. For deposits, it verifies that BTC has been locked on the Bitcoin network before minting the corresponding cBTC on Citrea. For withdrawals, it locks cBTC and stores the information required for the user to withdraw BTC on the Bitcoin network.


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

1.  **Bitcoin Transaction**: A user sends a fixed amount of BTC (`depositAmount`) to the bridge's Taproot address on the Bitcoin network. This transaction is called the deposit transaction, then the N-of-N moves this BTC to a specific address to indicate the deposit is accepted. This transaction is called the `moveTx`, this is the transaction that we prove its inclusion on the Bitcoin through the `BitcoinLightClient`.
2.  **Witness Data**: The `moveTx` is constructed with a specific witness. This witness includes:
    -   A script that contains the recipient's Citrea address (a 20-byte address).
    -   A predefined `depositPrefix` and `depositSuffix` within the script.
    -   A Schnorr signature from the N-of-N.
3.  **Relaying to Citrea**: Once the move transaction is confirmed, the deposit relayed to the sequencer which has a seperate pool for the deposit transactions. Then a system transaction calling the `deposit()` function on `Bridge.sol` is created.
4.  **On-Chain Verification**: The `deposit()` function executes a series of critical checks:
    -   **Inclusion Proof**: It uses the `BitcoinLightClient` to validate the provided Merkle proof, ensuring the transaction is final on Bitcoin.
    -   **Signature Verification**: It reconstructs the BIP-341 Taproot sighash and calls the precompile at `0x200` to verify the operators' Schnorr signature. This confirms the transaction's authenticity.
    -   **Script Validation**: It parses the witness script to confirm it matches the required format (`depositPrefix` + `recipient_address` + `depositSuffix`).
    -   **Replay Protection**: It records the Bitcoin transaction ID (`txId`) and ensures it cannot be used for a deposit more than once.
5.  **Minting cBTC**: If all validations pass, the contract extracts the recipient's address from the script and credits their account with the `depositAmount` of cBTC on Citrea. If the transfer fails, the funds are sent to a `failedDepositVault`.

## Withdrawal Flow: Citrea to Bitcoin

The withdrawal process moves assets from Citrea back to Bitcoin.

1.  **Initiate Withdrawal**: A user calls the `withdraw()` or `batchWithdraw()` function on the bridge contract. To do this, they must send the fixed `depositAmount` of cBTC to the contract. They also specify a Bitcoin ANYONECANPAY UTXO (`txId` and `outputId`) where they wish to receive the funds. 
2.  **Request Queue**: The contract records this request in a public `withdrawalUTXOs` array. This array serves as a queue of pending withdrawals for the operators to process.
3.  **`safeWithdraw()`**: The contract also provides a `safeWithdraw` function. This method offers users greater security by doing extra security checks such as verifying user's signature, and verifying the inclusion of the transaction.
