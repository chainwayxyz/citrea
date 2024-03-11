// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IL1BlockHashList {
    function setBlockHash(bytes32) external;
    function getBlockHash(uint256) external view returns (bytes32);
}