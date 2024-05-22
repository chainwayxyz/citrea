// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GasConsumer {
    uint256[] public arr;

    bytes32[] public hashes;

    function storageConsume() public {
        for (uint i = 0; i < 100; i++) {
            arr.push(i);
        }
    }

    function keccakConsume() public {
        for (uint i = 0; i < 100; i++) {
            hashes.push(keccak256(abi.encodePacked(i)));
        }
    }
}
