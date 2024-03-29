// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../lib/Ownable.sol";
import "./interfaces/IL1BlockHashList.sol";

/// @title A system contract that stores block hashes and merkle roots of L1 blocks
/// @author Citrea

contract L1BlockHashList is Ownable, IL1BlockHashList {
    mapping(uint256 => bytes32) public blockHashes;
    mapping(bytes32 => bytes32) public witnessRoots;
    uint256 public blockNumber;

    event BlockInfoAdded(uint256 blockNumber, bytes32 blockHash, bytes32 merkleRoot);
    constructor() Ownable(){ }

    /// @notice Sets the initial value for the block number, can only be called once
    /// @param _blockNumber The L1 block number that is associated with the genesis block of Citrea
    function initializeBlockNumber(uint256 _blockNumber) external onlyOwner {
        require(blockNumber == 0, "Already initialized");
        blockNumber = _blockNumber;
    }

    /// @notice Sets the block hash and witness root for a given block
    /// @notice Can only be called after the initial block number is set
    /// @dev The block number is incremented by the contract as no block info should be overwritten or skipped
    /// @param _blockHash The hash of the current L1 block
    /// @param _witnessRoot The witness root of the current L1 block 
    function setBlockInfo(bytes32 _blockHash, bytes32 _witnessRoot) external onlyOwner {
        uint256 _blockNumber = blockNumber;
        require(_blockNumber != 0, "Not initialized");
        blockHashes[_blockNumber] = _blockHash;
        blockNumber = _blockNumber + 1;
        witnessRoots[_blockHash] = _witnessRoot;
        emit BlockInfoAdded(blockNumber, _blockHash, _witnessRoot);
    }

    /// @param _blockNumber The number of the block to get the hash for
    /// @return The block hash for the given block
    function getBlockHash(uint256 _blockNumber) external view returns (bytes32) {
        return blockHashes[_blockNumber];
    }

    /// @param _blockHash The block hash of the block to get the witness root for
    /// @return The witness root for the given block
    function getWitnessRootByHash(bytes32 _blockHash) external view returns (bytes32) {
        return witnessRoots[_blockHash];
    }

    /// @param _blockNumber The block number of the block to get the witness root for
    /// @return The merkle root for the given block
    function getWitnessRootByNumber(uint256 _blockNumber) external view returns (bytes32) {
        return witnessRoots[blockHashes[_blockNumber]];
    }

    function verifyInclusion(bytes32 _blockHash, bytes32 _wtxId, bytes32[] calldata _proof) external view returns (bool) {
        return _verifyInclusion(_blockHash, _wtxId, _proof);
    }

    function verifyInclusion(uint256 _blockNumber, bytes32 _wtxId, bytes32[] calldata _proof) external view returns (bool) {
        return _verifyInclusion(blockHashes[_blockNumber], _wtxId, _proof);
    }

    function _verifyInclusion(bytes32 _blockHash, bytes32 _wtxId, bytes32[] calldata _proof) internal view returns (bool) {
        bytes32 result = _wtxId;
        for (uint256 i = 0; i < _proof.length; i++) {
            result = hash256(abi.encodePacked(result, _proof[i]));
        }
        return result == witnessRoots[_blockHash];
    }

    function hash256(bytes memory _bytes) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(_bytes)));
    }
}
