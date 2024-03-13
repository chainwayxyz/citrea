// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IL1BlockHashList {
    function initializeBlockNumber(uint256) external;
    function setBlockInfo(bytes32, bytes32) external;
    function getBlockHash(uint256) external view returns (bytes32);
    function getMerkleRootByHash(bytes32) external view returns (bytes32);
    function getMerkleRootByNumber(uint256) external view returns (bytes32);
}