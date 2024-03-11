// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../lib/Ownable.sol";
import "./interfaces/IL1BlockHashList.sol";

contract L1BlockHashList is Ownable, IL1BlockHashList {
    mapping(uint256 => bytes32) public blockHashes;
    mapping(bytes32 => bytes32) public merkleRoots;
    uint256 public blockNumber;

    event BlockInfoAdded(uint256 blockNumber, bytes32 blockHash, bytes32 merkleRoot);
    constructor() Ownable(){ }

    function setBlockInfo(bytes32 _blockHash, bytes32 _merkleRoot) public onlyOwner {
        blockHashes[blockNumber++] = _blockHash;
        merkleRoots[_blockHash] = _merkleRoot;
        emit BlockInfoAdded(blockNumber, _blockHash, _merkleRoot);
    }

    function getBlockHash(uint256 _blockNumber) public view returns (bytes32) {
        return blockHashes[_blockNumber];
    }

    function getMerkleRootFromBlockHash(bytes32 _blockHash) public view returns (bytes32) {
        return merkleRoots[_blockHash];
    }

    function getMerkleRootFromBlockNumber(uint256 _blockNumber) public view returns (bytes32) {
        return merkleRoots[blockHashes[_blockNumber]];
    }
}
