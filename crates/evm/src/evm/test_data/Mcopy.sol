// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.28;

contract Mcopy {

    function memoryCopy() external returns (bytes32 x) {
        assembly {
            mstore(0x20, 0x50)  // Store 0x50 at word 1 in memory
            mcopy(0, 0x20, 0x20)  // Copies 0x50 to word 0 in memory
            x := mload(0)    // Returns 32 bytes "0x50"
            sstore(0, x)  // Stores 0x50 at storage slot 0
        }
    }
}