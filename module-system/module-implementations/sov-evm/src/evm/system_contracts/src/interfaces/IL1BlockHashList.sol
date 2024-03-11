// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IL1BlockHashList {
    function setBlockInfo(bytes32, bytes32) external;
    function getBlockHash(uint256) external view returns (bytes32);
    function getMerkleRootFromBlockHash(bytes32) external view returns (bytes32);
    function getMerkleRootFromBlockNumber(uint256) external view returns (bytes32);
}