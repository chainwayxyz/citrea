// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract SelfdestructingConstructor {
    // Constructor with an address parameter
    constructor(address payable recipient) payable {
        // Call selfdestruct to send the contract's balance to the recipient
        selfdestruct(recipient);
    }
}