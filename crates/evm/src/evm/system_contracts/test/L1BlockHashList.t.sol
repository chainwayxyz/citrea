// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/L1BlockHashList.sol";

contract L1BlockHashListTest is Test {
    L1BlockHashList l1BlockHashList;
    bytes32 mockBlockHash = bytes32(keccak256("CITREA_TEST"));
    bytes32 mockWitnessRoot = bytes32(keccak256("CITREA"));
    uint256 constant INITIAL_BLOCK_NUMBER = 505050;
    address constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);

    function setUp() public {
        l1BlockHashList = new L1BlockHashList();
        vm.startPrank(SYSTEM_CALLER);
    }

    function testSetBlockInfo() public {
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        l1BlockHashList.setBlockInfo(mockBlockHash, mockWitnessRoot);
        assertEq(l1BlockHashList.getBlockHash(INITIAL_BLOCK_NUMBER), mockBlockHash);
        assertEq(l1BlockHashList.getWitnessRootByHash(mockBlockHash), mockWitnessRoot);
        assertEq(l1BlockHashList.getWitnessRootByNumber(INITIAL_BLOCK_NUMBER), mockWitnessRoot);
    }

    function testCannotReinitalize() public {
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        vm.expectRevert("Already initialized");
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER - 10);
    }

    function testNonSystemCannotSetBlockInfo() public {
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        vm.startPrank(address(0x1));
        vm.expectRevert("caller is not the system caller");
        l1BlockHashList.setBlockInfo(mockBlockHash, mockWitnessRoot);
    }

    function testNonSystemCannotInitializeBlockNumber() public {
        vm.stopPrank();
        vm.prank(address(0x1));
        vm.expectRevert("caller is not the system caller");
        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
    }

    function testCannotSetInfoWithoutInitialize() public {
        vm.expectRevert("Not initialized");
        l1BlockHashList.setBlockInfo(mockBlockHash, mockWitnessRoot);
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
        // Bitcoin Block 553724
        // wtxId 0: 0000000000000000000000000000000000000000000000000000000000000000 (coinbase)
        // wtxId 1: A28E549DC50610430BF7E224EFFD50DB0662356780C934AF0F1A9EB346D50087 (little endian)
        // wtxId 2: 87CBCB26EF9618F1363C0B0AE62C3AB6DE1DAF67FA6404C416A4D36059AB4BC5 (little endian)
        // wtxId 3: 85770DFEB29679FDB24E7CA87CA7D162962F6247269282F155F99E0061E31DE5 (little endian)
        // wtx root: DBEE9A868A8CAA2A1DDF683AF1642A88DFB7AC7CE3ECB5D043586811A41FDBF2 (little endian)
        bytes32 root = hex"DBEE9A868A8CAA2A1DDF683AF1642A88DFB7AC7CE3ECB5D043586811A41FDBF2";
        l1BlockHashList.setBlockInfo(mockBlockHash, root);
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = hex"0000000000000000000000000000000000000000000000000000000000000000";
        proof[1] = hex"6B1DAB5721B7B8D68B2C7F795D689998A35EFED7E5C99E12E6C8D5C587A1628D";
        bytes32 wtxId = hex"A28E549DC50610430BF7E224EFFD50DB0662356780C934AF0F1A9EB346D50087";
        assert(l1BlockHashList.verifyInclusion(mockBlockHash, wtxId, abi.encodePacked(proof), 1));
        assert(l1BlockHashList.verifyInclusion(INITIAL_BLOCK_NUMBER, wtxId, abi.encodePacked(proof), 1));
    }
}