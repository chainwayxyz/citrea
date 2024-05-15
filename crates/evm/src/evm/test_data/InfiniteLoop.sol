// SPDX-License-Identifier: GPL-3

pragma solidity ^0.8.0;

// solc --abi --bin  InfiniteLoop.sol  -o . --overwrite
contract InfiniteLoop {
    // Function to infinitely loop and do nothing.
    function infiniteLoop() pure public {
        uint256 a = 0;
        while (true) {
            ++a;
        }
    }
}
