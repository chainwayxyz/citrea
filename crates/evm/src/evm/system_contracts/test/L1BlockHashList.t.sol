// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/L1BlockHashList.sol";

contract L1BlockHashListTest is Test {
    L1BlockHashList l1BlockHashList;
    bytes32 randomBlockHash = bytes32(keccak256("CITREA_TEST"));
    bytes32 randomMerkleRoot = bytes32(keccak256("CITREA"));
    uint256 constant INITIAL_BLOCK_NUMBER = 505050;

    function setUp() public {
        l1BlockHashList = new L1BlockHashList();
    }

    function testSetBlockInfo() public {
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        l1BlockHashList.setBlockInfo(randomBlockHash, randomMerkleRoot);
        assertEq(l1BlockHashList.getBlockHash(INITIAL_BLOCK_NUMBER), randomBlockHash);
        assertEq(l1BlockHashList.getMerkleRootByHash(randomBlockHash), randomMerkleRoot);
        assertEq(l1BlockHashList.getMerkleRootByNumber(INITIAL_BLOCK_NUMBER), randomMerkleRoot);
    }

    function testCannotReinitalize() public {
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        vm.expectRevert("Already initialized");
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER - 10);
    }

    function testNonOwnerCannotSetBlockInfo() public {
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        vm.startPrank(address(0x1));
        vm.expectRevert("Caller is not owner");
        l1BlockHashList.setBlockInfo(randomBlockHash, randomMerkleRoot);
    }

    function testNonOwnerCannotInitializeBlockNumber() public {
        vm.startPrank(address(0x1));
        vm.expectRevert("Caller is not owner");
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
    }

    function testCannotSetInfoWithoutInitialize() public {
        vm.expectRevert("Not initialized");
        l1BlockHashList.setBlockInfo(randomBlockHash, randomMerkleRoot);
    }

    function testBlockInfoAvailableAfterManyWrites() public {
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        for (uint256 i = 0; i < 100; i++) {
            bytes32 blockHash = keccak256(abi.encodePacked(i));
            bytes32 root = keccak256(abi.encodePacked(blockHash));
            l1BlockHashList.setBlockInfo(blockHash, root);
            assertEq(l1BlockHashList.getBlockHash(i + INITIAL_BLOCK_NUMBER), blockHash);
            assertEq(l1BlockHashList.getMerkleRootByHash(blockHash), root);
            assertEq(l1BlockHashList.getMerkleRootByNumber(i + INITIAL_BLOCK_NUMBER), root);
        }

        bytes32 zeroth_hash = keccak256(abi.encodePacked(uint(0)));
        bytes32 zeroth_root = keccak256(abi.encodePacked(zeroth_hash));
        assertEq(l1BlockHashList.getBlockHash(INITIAL_BLOCK_NUMBER), zeroth_hash);
        assertEq(l1BlockHashList.getMerkleRootByHash(zeroth_hash), zeroth_root);
        assertEq(l1BlockHashList.getMerkleRootByNumber(INITIAL_BLOCK_NUMBER), zeroth_root);
    }
}