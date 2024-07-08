// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./interfaces/IBitcoinLightClient.sol";
import "bitcoin-spv/solidity/contracts/ValidateSPV.sol";
import "openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";

/// @title A system contract that stores block hashes and witness root hashes of L1 blocks
/// @author Citrea

//  WARNING: Integrators must be aware of the following points:
// - Block hash getters returning 0 value means no such block is recorded
// - Witness root getters returning 0 value doesn't necessarily mean no such block is recorded, as 0 is also a valid witness root hash in the case of a 1 transaction block

contract BitcoinLightClient is IBitcoinLightClient {
    uint256 public blockNumber;
    address public constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);
    mapping(uint256 => bytes32) public blockHashes;
    mapping(bytes32 => bytes32) public witnessRoots;
    
    event BlockInfoAdded(uint256 blockNumber, bytes32 blockHash, bytes32 merkleRoot);

    modifier onlySystem() {
        require(msg.sender == SYSTEM_CALLER, "caller is not the system caller");
        _;
    }

    /// @notice Sets the initial value for the block number, can only be called once
    /// @param _blockNumber L1 block number that is associated with the genesis block of Citrea
    function initializeBlockNumber(uint256 _blockNumber) external onlySystem {
        require(blockNumber == 0, "Already initialized");
        blockNumber = _blockNumber;
    }

    /// @notice Sets the block hash and witness root for a given block
    /// @notice Can only be called after the initial block number is set
    /// @dev Block number is incremented by the contract as no block info should be overwritten or skipped
    /// @param _blockHash Hash of the current L1 block
    /// @param _witnessRoot Witness root of the current L1 block, must be in little endian 
    function setBlockInfo(bytes32 _blockHash, bytes32 _witnessRoot) external onlySystem {
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
        return ValidateSPV.prove(_wtxId, _witnessRoot, _proof, _index);
    }
}
