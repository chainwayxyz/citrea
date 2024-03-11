// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/L1BlockHashList.sol";

contract L1BlockHashListTest is Test {
    L1BlockHashList l1BlockHashList;
    bytes32 randomBlockHash = bytes32(keccak256("CITREA_TEST"));

    function setUp() public {
        l1BlockHashList = new L1BlockHashList();
    }

    function testSetBlockHash() public {
        l1BlockHashList.setBlockHash(randomBlockHash);
        assertEq(l1BlockHashList.getBlockHash(0), randomBlockHash);
    }

    function testNonOwnerCannotSetBlockHash() public {
        vm.startPrank(address(0x1));
        vm.expectRevert("Caller is not owner");
        l1BlockHashList.setBlockHash(randomBlockHash);
    }

    function testBlockHashAvailableAfterManyWrites() public {
        for (uint256 i = 0; i < 100; i++) {
            bytes32 blockHash = keccak256(abi.encodePacked(i));
            l1BlockHashList.setBlockHash(blockHash);
            assertEq(l1BlockHashList.getBlockHash(i), blockHash);
        }

        bytes32 zeroth_hash = keccak256(abi.encodePacked(uint(0)));
        assertEq(l1BlockHashList.getBlockHash(0), zeroth_hash);
    }
}