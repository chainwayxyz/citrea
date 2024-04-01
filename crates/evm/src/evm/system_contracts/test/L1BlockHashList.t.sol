// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/L1BlockHashList.sol";

contract L1BlockHashListTest is Test {
    L1BlockHashList l1BlockHashList;
    bytes32 randomBlockHash = bytes32(keccak256("CITREA_TEST"));
    bytes32 randomWitnessRoot = bytes32(keccak256("CITREA"));
    uint256 constant INITIAL_BLOCK_NUMBER = 505050;

    function setUp() public {
        l1BlockHashList = new L1BlockHashList();
    }

    function testSetBlockInfo() public {
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        l1BlockHashList.setBlockInfo(randomBlockHash, randomWitnessRoot);
        assertEq(l1BlockHashList.getBlockHash(INITIAL_BLOCK_NUMBER), randomBlockHash);
        assertEq(l1BlockHashList.getWitnessRootByHash(randomBlockHash), randomWitnessRoot);
        assertEq(l1BlockHashList.getWitnessRootByNumber(INITIAL_BLOCK_NUMBER), randomWitnessRoot);
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
        l1BlockHashList.setBlockInfo(randomBlockHash, randomWitnessRoot);
    }

    function testNonOwnerCannotInitializeBlockNumber() public {
        vm.startPrank(address(0x1));
        vm.expectRevert("Caller is not owner");
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
    }

    function testCannotSetInfoWithoutInitialize() public {
        vm.expectRevert("Not initialized");
        l1BlockHashList.setBlockInfo(randomBlockHash, randomWitnessRoot);
    }

    function testBlockInfoAvailableAfterManyWrites() public {
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        for (uint256 i = 0; i < 100; i++) {
            bytes32 blockHash = keccak256(abi.encodePacked(i));
            bytes32 root = keccak256(abi.encodePacked(blockHash));
            l1BlockHashList.setBlockInfo(blockHash, root);
            assertEq(l1BlockHashList.getBlockHash(i + INITIAL_BLOCK_NUMBER), blockHash);
            assertEq(l1BlockHashList.getWitnessRootByHash(blockHash), root);
            assertEq(l1BlockHashList.getWitnessRootByNumber(i + INITIAL_BLOCK_NUMBER), root);
        }

        bytes32 zeroth_hash = keccak256(abi.encodePacked(uint(0)));
        bytes32 zeroth_root = keccak256(abi.encodePacked(zeroth_hash));
        assertEq(l1BlockHashList.getBlockHash(INITIAL_BLOCK_NUMBER), zeroth_hash);
        assertEq(l1BlockHashList.getWitnessRootByHash(zeroth_hash), zeroth_root);
        assertEq(l1BlockHashList.getWitnessRootByNumber(INITIAL_BLOCK_NUMBER), zeroth_root);
    }

    function testVerifyInclusion() public {
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        // 2975efaf781b03df6a635e8f38160492413a311b083d4dc640c524782f695ccc
        // 4cf9d14bae01332bbd96fb4d46731c024c0d82ffdfcc70a4fa97aa7395e38f7d
        bytes32 root = hex"1603c518f01939a30b46000912288d827588d5bbc70a04098f731c0c5b978c1b";
        l1BlockHashList.setBlockInfo(randomBlockHash, root);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = hex"4cf9d14bae01332bbd96fb4d46731c024c0d82ffdfcc70a4fa97aa7395e38f7d";
        bytes32 wtxId = hex"0000000000000000000000000000000000000000000000000000000000000000";
        assert(l1BlockHashList.verifyInclusion(randomBlockHash, wtxId, proof));
        assert(l1BlockHashList.verifyInclusion(INITIAL_BLOCK_NUMBER, wtxId, proof));
    }
}