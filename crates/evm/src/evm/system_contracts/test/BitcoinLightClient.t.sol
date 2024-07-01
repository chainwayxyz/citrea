// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/BitcoinLightClient.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";


contract Placeholder is UUPSUpgradeable { 
    function _authorizeUpgrade(address newImplementation) internal override {} 
}

contract FalseClient is BitcoinLightClient {
    function getBlockHashFalse(uint256 _blockNumber) public view returns (bytes32) {
        return keccak256("false");
    }
}


contract BitcoinLightClientTest is Test {
    BitcoinLightClient bitcoinLightClient = BitcoinLightClient(address(0x3100000000000000000000000000000000000001));
    bytes32 mockBlockHash = bytes32(keccak256("CITREA_TEST"));
    bytes32 mockWitnessRoot = bytes32(keccak256("CITREA"));
    uint256 constant INITIAL_BLOCK_NUMBER = 505050;
    address constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);
    address owner = address(0x013);


    function setUp() public {
        address lightClient_impl = address(new BitcoinLightClient());
        address placeholder = address(new Placeholder());
        address erc1967_impl = address(new ERC1967Proxy(placeholder, ""));
        vm.etch(address(bitcoinLightClient), erc1967_impl.code);
        bytes32 IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        bytes32 OWNER_SLOT = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;
        vm.store(address(bitcoinLightClient), IMPLEMENTATION_SLOT, bytes32(uint256(uint160(lightClient_impl))));
        vm.store(address(bitcoinLightClient), OWNER_SLOT, bytes32(uint256(uint160(owner))));
        vm.startPrank(SYSTEM_CALLER);
    }

    function testSetBlockInfo() public {
        bitcoinLightClient.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        bitcoinLightClient.setBlockInfo(mockBlockHash, mockWitnessRoot);
        assertEq(bitcoinLightClient.getBlockHash(INITIAL_BLOCK_NUMBER), mockBlockHash);
        assertEq(bitcoinLightClient.getWitnessRootByHash(mockBlockHash), mockWitnessRoot);
        assertEq(bitcoinLightClient.getWitnessRootByNumber(INITIAL_BLOCK_NUMBER), mockWitnessRoot);
    }

    function testCannotReinitalize() public {
        bitcoinLightClient.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        vm.expectRevert("Already initialized");
        bitcoinLightClient.initializeBlockNumber(INITIAL_BLOCK_NUMBER - 10);
    }

    function testNonSystemCannotSetBlockInfo() public {
        bitcoinLightClient.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        vm.startPrank(address(0x1));
        vm.expectRevert("caller is not the system caller");
        bitcoinLightClient.setBlockInfo(mockBlockHash, mockWitnessRoot);
    }

    function testNonSystemCannotInitializeBlockNumber() public {
        vm.stopPrank();
        vm.prank(address(0x1));
        vm.expectRevert("caller is not the system caller");
        bitcoinLightClient.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
    }

    function testCannotSetInfoWithoutInitialize() public {
        vm.expectRevert("Not initialized");
        bitcoinLightClient.setBlockInfo(mockBlockHash, mockWitnessRoot);
    }

    function testBlockInfoAvailableAfterManyWrites() public {
        bitcoinLightClient.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        for (uint256 i = 0; i < 100; i++) {
            bytes32 blockHash = keccak256(abi.encodePacked(i));
            bytes32 root = keccak256(abi.encodePacked(blockHash));
            bitcoinLightClient.setBlockInfo(blockHash, root);
            assertEq(bitcoinLightClient.getBlockHash(i + INITIAL_BLOCK_NUMBER), blockHash);
            assertEq(bitcoinLightClient.getWitnessRootByHash(blockHash), root);
            assertEq(bitcoinLightClient.getWitnessRootByNumber(i + INITIAL_BLOCK_NUMBER), root);
        }

        bytes32 zeroth_hash = keccak256(abi.encodePacked(uint(0)));
        bytes32 zeroth_root = keccak256(abi.encodePacked(zeroth_hash));
        assertEq(bitcoinLightClient.getBlockHash(INITIAL_BLOCK_NUMBER), zeroth_hash);
        assertEq(bitcoinLightClient.getWitnessRootByHash(zeroth_hash), zeroth_root);
        assertEq(bitcoinLightClient.getWitnessRootByNumber(INITIAL_BLOCK_NUMBER), zeroth_root);
    }

    function testVerifyInclusion() public {
        bitcoinLightClient.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        // Bitcoin Block 553724
        // wtxId 0: 0000000000000000000000000000000000000000000000000000000000000000 (coinbase)
        // wtxId 1: A28E549DC50610430BF7E224EFFD50DB0662356780C934AF0F1A9EB346D50087 (little endian)
        // wtxId 2: 87CBCB26EF9618F1363C0B0AE62C3AB6DE1DAF67FA6404C416A4D36059AB4BC5 (little endian)
        // wtxId 3: 85770DFEB29679FDB24E7CA87CA7D162962F6247269282F155F99E0061E31DE5 (little endian)
        // wtx root: DBEE9A868A8CAA2A1DDF683AF1642A88DFB7AC7CE3ECB5D043586811A41FDBF2 (little endian)
        bytes32 root = hex"DBEE9A868A8CAA2A1DDF683AF1642A88DFB7AC7CE3ECB5D043586811A41FDBF2";
        bitcoinLightClient.setBlockInfo(mockBlockHash, root);
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = hex"0000000000000000000000000000000000000000000000000000000000000000";
        proof[1] = hex"6B1DAB5721B7B8D68B2C7F795D689998A35EFED7E5C99E12E6C8D5C587A1628D";
        bytes32 wtxId = hex"A28E549DC50610430BF7E224EFFD50DB0662356780C934AF0F1A9EB346D50087";
        assert(bitcoinLightClient.verifyInclusion(mockBlockHash, wtxId, abi.encodePacked(proof), 1));
        assert(bitcoinLightClient.verifyInclusion(INITIAL_BLOCK_NUMBER, wtxId, abi.encodePacked(proof), 1));
    }

    function testUpgrade() public {
        address newImpl = address(new FalseClient());
        vm.stopPrank();
        vm.prank(owner);
        bitcoinLightClient.upgradeToAndCall(newImpl, "");
        assertEq(FalseClient(address(bitcoinLightClient)).getBlockHashFalse(0), keccak256("false"));
    }

    function testNonOwnerCannotUpgrade() public {
        vm.stopPrank();
        vm.prank(address(0x1));
        address newImpl = address(new FalseClient());
        vm.expectRevert();
        bitcoinLightClient.upgradeToAndCall(newImpl, "");
    }

    function testOwnerCanChangeAndUpgrade() public {
        address newImpl = address(new FalseClient());
        vm.stopPrank();
        address newOwner = address(0x051323242);
        vm.prank(owner);
        bitcoinLightClient.transferOwnership(newOwner);
        vm.startPrank(newOwner);
        bitcoinLightClient.acceptOwnership();
        bitcoinLightClient.upgradeToAndCall(newImpl, "");
        assertEq(FalseClient(address(bitcoinLightClient)).getBlockHashFalse(0), keccak256("false"));
    }
}