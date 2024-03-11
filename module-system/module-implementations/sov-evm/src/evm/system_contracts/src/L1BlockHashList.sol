// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../lib/Ownable.sol";
import "./interfaces/IL1BlockHashList.sol";

contract L1BlockHashList is Ownable, IL1BlockHashList {
    mapping(uint256 => bytes32) public blockHashes;
    uint256 public blockNumber;

    event BlockHashAdded(uint256 blockNumber, bytes32 blockHash);
    constructor() Ownable(){ }

    function setBlockHash(bytes32 blockHash) public onlyOwner {
        blockHashes[blockNumber++] = blockHash;
        emit BlockHashAdded(blockNumber, blockHash);
    }

    function getBlockHash(uint256 _blockNumber) public view returns (bytes32) {
        return blockHashes[_blockNumber];
    }
}
