// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../lib/Ownable.sol";
import "./interfaces/IL1BlockHashList.sol";
import "bitcoin-spv/solidity/contracts/ValidateSPV.sol";

/// @title A system contract that stores block hashes and merkle roots of L1 blocks
/// @author Citrea

contract L1BlockHashList is Ownable, IL1BlockHashList {
    mapping(uint256 => bytes32) public blockHashes;
    mapping(bytes32 => bytes32) public witnessRoots;
    uint256 public blockNumber;

    event BlockInfoAdded(uint256 blockNumber, bytes32 blockHash, bytes32 merkleRoot);
    constructor() Ownable(){ }

    /// @notice Sets the initial value for the block number, can only be called once
    /// @param _blockNumber L1 block number that is associated with the genesis block of Citrea
    function initializeBlockNumber(uint256 _blockNumber) external onlyOwner {
        require(blockNumber == 0, "Already initialized");
        blockNumber = _blockNumber;
    }

    /// @notice Sets the block hash and witness root for a given block
    /// @notice Can only be called after the initial block number is set
    /// @dev Block number is incremented by the contract as no block info should be overwritten or skipped
    /// @param _blockHash Hash of the current L1 block
    /// @param _witnessRoot Witness root of the current L1 block, must be in little endian 
    function setBlockInfo(bytes32 _blockHash, bytes32 _witnessRoot) external onlyOwner {
        uint256 _blockNumber = blockNumber;
        require(_blockNumber != 0, "Not initialized");
        blockHashes[_blockNumber] = _blockHash;
        blockNumber = _blockNumber + 1;
        witnessRoots[_blockHash] = _witnessRoot;
        emit BlockInfoAdded(blockNumber, _blockHash, _witnessRoot);
    }

    /// @param _blockNumber Number of the block to get the hash for
    /// @return Block hash for the given block
    function getBlockHash(uint256 _blockNumber) external view returns (bytes32) {
        return blockHashes[_blockNumber];
    }

    /// @param _blockHash Block hash of the block to get the witness root for
    /// @return Witness root for the given block
    function getWitnessRootByHash(bytes32 _blockHash) external view returns (bytes32) {
        return witnessRoots[_blockHash];
    }

    /// @param _blockNumber Block number of the block to get the witness root for
    /// @return Merkle root for the given block
    function getWitnessRootByNumber(uint256 _blockNumber) external view returns (bytes32) {
        return witnessRoots[blockHashes[_blockNumber]];
    }

    /// @notice Verifies the inclusion of a witness transaction ID in the witness root hash of a block
    /// @dev Witness transaction ID and proof elements must be in little endian
    /// @param _blockHash Block hash of the block
    /// @param _wtxId Witness transaction ID
    /// @param _proof Merkle proof
    /// @param _index Index of the transaction
    /// @return If the witness transaction ID is included in the witness root hash of the block
    function verifyInclusion(bytes32 _blockHash, bytes32 _wtxId, bytes calldata _proof, uint256 _index) external view returns (bool) {
        return _verifyInclusion(_blockHash, _wtxId, _proof, _index);
    }

    /// @notice Verifies the inclusion of a witness transaction ID in the witness root hash of a block
    /// @dev Witness transaction ID and proof elements must be in little endian
    /// @param _blockNumber Block number of the block
    /// @param _wtxId Witness transaction ID
    /// @param _proof Merkle proof
    /// @param _index Index of the transaction
    /// @return If the witness transaction ID is included in the witness root hash of the block
    function verifyInclusion(uint256 _blockNumber, bytes32 _wtxId, bytes calldata _proof, uint256 _index) external view returns (bool) {
        return _verifyInclusion(blockHashes[_blockNumber], _wtxId, _proof, _index);
    }

    function _verifyInclusion(bytes32 _blockHash, bytes32 _wtxId, bytes calldata _proof, uint256 _index) internal view returns (bool) {
        bytes32 _witnessRoot = witnessRoots[_blockHash];
        require(_wtxId != bytes32(0), "Cannot verify coinbase transaction");
        return ValidateSPV.prove(_wtxId, _witnessRoot, _proof, _index);
    }
}
