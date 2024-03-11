// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/L1BlockHashList.sol";

contract L1BlockHashListTest is Test {
    L1BlockHashList l1BlockHashList;
    bytes32 randomBlockHash = bytes32(keccak256("CITREA_TEST"));
    bytes32 randomMerkleRoot = bytes32(keccak256("CITREA"));

    function setUp() public {
        l1BlockHashList = new L1BlockHashList();
    }

    function testSetBlockInfo() public {
        l1BlockHashList.setBlockInfo(randomBlockHash, randomMerkleRoot);
        assertEq(l1BlockHashList.getBlockHash(0), randomBlockHash);
        assertEq(l1BlockHashList.getMerkleRootFromBlockHash(randomBlockHash), randomMerkleRoot);
        assertEq(l1BlockHashList.getMerkleRootFromBlockNumber(0), randomMerkleRoot);
    }

    function testNonOwnerCannotSetBlockInfo() public {
        vm.startPrank(address(0x1));
        vm.expectRevert("Caller is not owner");
        l1BlockHashList.setBlockInfo(randomBlockHash, randomMerkleRoot);
    }

    function testBlockInfoAvailableAfterManyWrites() public {
        for (uint256 i = 0; i < 100; i++) {
            bytes32 blockHash = keccak256(abi.encodePacked(i));
            bytes32 root = keccak256(abi.encodePacked(blockHash));
            l1BlockHashList.setBlockInfo(blockHash, root);
            assertEq(l1BlockHashList.getBlockHash(i), blockHash);
            assertEq(l1BlockHashList.getMerkleRootFromBlockHash(blockHash), root);
            assertEq(l1BlockHashList.getMerkleRootFromBlockNumber(i), root);
        }

        bytes32 zeroth_hash = keccak256(abi.encodePacked(uint(0)));
        bytes32 zeroth_root = keccak256(abi.encodePacked(zeroth_hash));
        assertEq(l1BlockHashList.getBlockHash(0), zeroth_hash);
        assertEq(l1BlockHashList.getMerkleRootFromBlockHash(zeroth_hash), zeroth_root);
        assertEq(l1BlockHashList.getMerkleRootFromBlockNumber(0), zeroth_root);
    }
}