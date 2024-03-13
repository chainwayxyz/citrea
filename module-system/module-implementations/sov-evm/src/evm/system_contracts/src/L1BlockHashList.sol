// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../lib/Ownable.sol";
import "./interfaces/IL1BlockHashList.sol";

/// @title A system contract that stores block hashes and merkle roots of L1 blocks
/// @author Citrea

contract L1BlockHashList is Ownable, IL1BlockHashList {
    mapping(uint256 => bytes32) public blockHashes;
    mapping(bytes32 => bytes32) public merkleRoots;
    uint256 public blockNumber;

    event BlockInfoAdded(uint256 blockNumber, bytes32 blockHash, bytes32 merkleRoot);
    constructor() Ownable(){ }

    /// @notice Sets the initial value for the block number, can only be called once
    /// @param _blockNumber The L1 block number that is associated with the genesis block of Citrea
    function initializeBlockNumber(uint256 _blockNumber) public onlyOwner {
        require(blockNumber == 0, "Already initialized");
        blockNumber = _blockNumber;
    }

    /// @notice Sets the block hash and merkle root for a given block
    /// @notice Can only be called after the initial block number is set
    /// @dev The block number is incremented by the contract as no block info should be overwritten or skipped
    /// @param _blockHash The hash of the current L1 block
    /// @param _merkleRoot The merkle root of the current L1 block 
    function setBlockInfo(bytes32 _blockHash, bytes32 _merkleRoot) public onlyOwner {
        uint256 _blockNumber = blockNumber;
        require(_blockNumber != 0, "Not initialized");
        blockHashes[_blockNumber] = _blockHash;
        blockNumber = _blockNumber + 1;
        merkleRoots[_blockHash] = _merkleRoot;
        emit BlockInfoAdded(blockNumber, _blockHash, _merkleRoot);
    }

    /// @param _blockNumber The number of the block to get the hash for
    /// @return The block hash for the given block
    function getBlockHash(uint256 _blockNumber) public view returns (bytes32) {
        return blockHashes[_blockNumber];
    }

    /// @param _blockHash The block hash of the block to get the merkle root for
    /// @return The merkle root for the given block
    function getMerkleRootByHash(bytes32 _blockHash) public view returns (bytes32) {
        return merkleRoots[_blockHash];
    }

    /// @param _blockNumber The block number of the block to get the merkle root for
    /// @return The merkle root for the given block
    function getMerkleRootByNumber(uint256 _blockNumber) public view returns (bytes32) {
        return merkleRoots[blockHashes[_blockNumber]];
    }
}
