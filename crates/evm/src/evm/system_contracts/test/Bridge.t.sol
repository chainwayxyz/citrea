// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/Bridge.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import "openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";



// !!! WARNINGS:
// !!! - Update `testDepositThenWithdraw` and `testBatchWithdraw` with proper testing of withdrawal tree root if this goes to production
// !!! - Write fuzz tests for deposit and withdraw actions with random Bitcoin txns if this goes to production

contract BridgeHarness is Bridge {
    // Overriding in harness is needed as internal functions are not accessible in the test
    function isBytesEqual_(bytes memory a, bytes memory b) public pure returns (bool result) {
        result = super.isBytesEqual(a, b);
    }
}

contract FalseBridge is Bridge {
    function falseFunc() public pure returns (bytes32) {
        return keccak256("false");
    }
}

contract BridgeTest is Test {
    using BytesLib for bytes;

    uint256 constant DEPOSIT_AMOUNT = 10 ether;
    BridgeHarness public bridge = BridgeHarness(address(0x3100000000000000000000000000000000000002));
    bytes2 flag = hex"0001";
    bytes4 version = hex"02000000";
    bytes vin = hex"01d2954591d05e99d0467f7b15aa4f8dfa41d4abb4da0b7bdfeb79ae8148a244550100000000fdffffff";
    bytes vout = hex"0285c79a3b0000000022512032dd3f3e100a141cd1327bb8b40937f5835f63e6d52187c69e4ab916a533deef4a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
    bytes4 locktime = hex"00000000";
    bytes witness = hex"03409dd5769e2cbd0c8eff9d9e059140d68d7df6317ecc7bc357cbf19c8b23a21f4a16f2840a3284cfb697c3e8abbd6062f67e4b8bae686007740e22480baba74cbf4a20a9dc2892380bf8245eb7a677ab166c98514ea6c5ce7946adbf4c05afb2bfbffdac00630663697472656114010101010101010101010101010101010101010108000000003b9aca006841c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51131a3022638eec69204e3337e4298c7df7ed343b11ac49ae2d0fbfb328860f9e";
    bytes depositScript = hex"4a20a9dc2892380bf8245eb7a677ab166c98514ea6c5ce7946adbf4c05afb2bfbffdac00630663697472656114";
    bytes scriptSuffix = hex"08000000003b9aca0068";
    bytes intermediate_nodes = hex"b28431f4e057e7ec90ddf35af056ce4c2ed281ae141ee70490e3ba09368523a7d0e5a0956e09b656576a4e458cf62fcda4cc320d0fbbff2a704db7ba0ae0a4e17eb013392c1d23d731e366e1d41493e5f5882480d861ad7e6caf74769e6e2db5";
    uint256 index = 6;

    address constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);
    address receiver = address(0x0101010101010101010101010101010101010101);
    address user = makeAddr("citrea_user");
    address owner = makeAddr("citrea_owner");
    address operator;
    uint256 constant INITIAL_BLOCK_NUMBER = 1;
    bytes32 witnessRoot = hex"9a989f7a75f6d685d5b85ada68f7829a41af692b3e82a7851a37b1d23c63fe78";
    bytes32 mockBlockhash = keccak256("CITREA_TEST");

    BitcoinLightClient bitcoinLightClient;

    ProxyAdmin proxyAdmin = ProxyAdmin(0x31fFFfFfFFFffFFFFFFfFFffffFFffffFfFFfffF);

    function setUp() public {
        proxyAdmin = new ProxyAdmin();
        vm.etch(address(proxyAdmin), address(proxyAdmin).code);
        vm.store(address(proxyAdmin), bytes32(0), bytes32(uint256(uint160(owner))));

        address bridgeImpl = address(new BridgeHarness());
        address proxy_impl = address(new TransparentUpgradeableProxy(bridgeImpl, address(proxyAdmin), ""));

        vm.etch(address(bridge), proxy_impl.code);

        bytes32 IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        bytes32 ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
        bytes32 OWNER_SLOT = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;

        vm.store(address(bridge), IMPLEMENTATION_SLOT, bytes32(uint256(uint160(bridgeImpl))));
        vm.store(address(bridge), ADMIN_SLOT, bytes32(uint256(uint160(address(proxyAdmin)))));
        vm.store(address(bridge), OWNER_SLOT, bytes32(uint256(uint160(owner))));

        vm.prank(SYSTEM_CALLER);
        bridge.initialize(depositScript, scriptSuffix, 10 ether);
        vm.deal(address(bridge), 21_000_000 ether);
        address lightClient_impl = address(new BitcoinLightClient());
        bitcoinLightClient = bridge.LIGHT_CLIENT();
        vm.etch(address(bitcoinLightClient), lightClient_impl.code);

        vm.startPrank(SYSTEM_CALLER);
        bitcoinLightClient.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        // Arbitrary blockhash as this is mock
        bitcoinLightClient.setBlockInfo(mockBlockhash, witnessRoot);
        vm.stopPrank();

        operator = bridge.operator();
    }

    function testDeposit() public {
        doDeposit();
        // Assert if asset transferred
        assertEq(receiver.balance, DEPOSIT_AMOUNT);
    }

    // TODO: Replace the logic of testing the root of withdrawal tree in a more proper manner if this goes into production
    function testDepositThenWithdraw() public {
        doDeposit();
        // Assert if transferred
        assertEq(receiver.balance, DEPOSIT_AMOUNT);

        // Assert if receiver can withdraw
        vm.startPrank(receiver);
        bytes32 txId = hex"1234"; // Dummy txId
        uint32 outputId = 2; // Dummy outputId
        uint256 withdrawalCount = bridge.getWithdrawalCount();
        bridge.withdraw{value: DEPOSIT_AMOUNT}(txId, outputId);

        // Assert if withdrawal address is stored properly
        (bytes32 _txId, uint32 _outputId) = bridge.withdrawalUTXOs(withdrawalCount);
        assertEq(_txId, txId);
        assertEq(_outputId, outputId);
        
        // Assert if tokens are burned from receiver
        assertEq(receiver.balance, 0);


        vm.stopPrank();
    }

    function testBatchWithdraw() public {
        vm.startPrank(user);
        vm.deal(address(user), DEPOSIT_AMOUNT * 10);
        bytes32[] memory btc_addresses = new bytes32[](10);
        uint32[] memory output_ids = new uint32[](10);
        for (uint i = 0; i < 10; i++) {
            btc_addresses[i] = bytes32(abi.encodePacked(i));
            output_ids[i] = uint32(i);
        }
        
        bridge.batchWithdraw{value: DEPOSIT_AMOUNT * 10}(btc_addresses, output_ids);
        

        for (uint i = 0; i < 10; i++) {
            (bytes32 _txId, uint32 _outputId) = bridge.withdrawalUTXOs(i);
            assertEq(_txId, btc_addresses[i]);
            assertEq(_outputId, output_ids[i]);
        }
        
        assertEq(user.balance, 0);
    }

    function testCannotBatchWithdrawWithWrongValue() public {
        vm.startPrank(user);
        vm.deal(address(user), 10 ether);
        bytes32[] memory btc_addresses = new bytes32[](10);
        uint32[] memory output_ids = new uint32[](10);
        for (uint i = 0; i < 10; i++) {
            btc_addresses[i] = bytes32(abi.encodePacked(i));
            output_ids[i] = uint32(i);
        }
        vm.expectRevert("Invalid withdraw amount");
        bridge.batchWithdraw{value: 9 ether}(btc_addresses, output_ids);
    }

    function testCannotDoubleDepositWithSameTx() public {
        doDeposit();
        vm.expectRevert("txId already spent");
        doDeposit();
    }

    function testCannotDepositWithFalseDepositScript() public {
        // False witness
        witness = hex"03409dd5769e2cbd0c8eff9d9e059140d68d7df6317ecc7bc357cbf19c8b23a21f4a16f2840a3284cfb697c3e8abbd6062f67e4b8bae686007740e22480baba74cbf4a20a9dc2892380bf8245eb7a677ab166c98514ea6c5ce7946adbf4c05afb2bfbffdac00630663697472656115010101010101010101010101010101010101010108000000003b9aca006841c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51131a3022638eec69204e3337e4298c7df7ed343b11ac49ae2d0fbfb328860f9e";
        witnessRoot = hex"95e2c12c1b0f16702e815a213abc8696c74793b8edecb78c122911dc9184578f";
        index = 0;
        intermediate_nodes = hex"";
        vm.startPrank(SYSTEM_CALLER);
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_2"), witnessRoot);
        
        vm.expectRevert("Invalid deposit script");
        // Incremented 1 block, that's why `doDeposit` is not used
        Bridge.TransactionParams memory depositParams = Bridge.TransactionParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER + 1, index);
        bridge.deposit(depositParams);
        vm.stopPrank();
    }

    function testCannotDepositWithATxNotInBlock() public {
        // Tries the hard coded txn on another block with a different witness root
        witnessRoot = hex"b615b861dae528f99e15f37cb755f9ee8a02be8bd870088e3f329cde8609730b";
        vm.startPrank(SYSTEM_CALLER);
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_2"), witnessRoot);

        vm.expectRevert("Transaction is not in block");
        Bridge.TransactionParams memory depositParams = Bridge.TransactionParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER + 1, index);
        bridge.deposit(depositParams);
    }

    function testCannotWithdrawWithInvalidAmount() public {
        doDeposit();

        // Assert if transferred
        assertEq(receiver.balance, DEPOSIT_AMOUNT);
        vm.stopPrank();

        // Assert if receiver cannot withdraw with invalid amount
        vm.startPrank(receiver);
        vm.expectRevert("Invalid withdraw amount");
        bridge.withdraw{value: DEPOSIT_AMOUNT - 1}(hex"1234", 2);
        vm.stopPrank();
    }

    function testNonOperatorCannotDeposit() public {
        vm.expectRevert("caller is not the operator");
        Bridge.TransactionParams memory depositParams = Bridge.TransactionParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER, index);
        bridge.deposit(depositParams);
    }

    function testCannotSetOperatorIfNotOwner() public {
        vm.startPrank(user);
        vm.expectRevert();
        bridge.setOperator(user);
    }

    function testCannotReinitialize() public {
        vm.expectRevert("Contract is already initialized");
        vm.prank(SYSTEM_CALLER);
        bridge.initialize(depositScript, scriptSuffix, 5);
    }

    function testCanChangeOperatorAndDeposit() public {
        vm.prank(owner);
        bridge.setOperator(user);
        operator = user;
        vm.stopPrank();
        doDeposit();
    }

    function testBytesEqual() public view {
        bytes memory a = hex"1234";
        bytes memory b = hex"1234";
        bytes memory c = hex"1235";
        bytes memory d = hex"c2ddf50500000000225120fc6eb6fa4fd4ed1e8519a7edfa171eddcedfbd0e0be49b5e531ef36e7e66eb05";
        bytes memory e = hex"c2ddf50500000000225120fc6eb6fa4fd4ed1e8519a7edfa171eddcedfbd0e0be49b5e531ef36e7e66eb06";
        bytes memory f = hex"c2ddf50500000000225120fc6eb6fa4fd4ed1e8519a7edfa171eddcedfbd0e0be49b5e531ef36e7e66eb05";

        assert(bridge.isBytesEqual_(a, b));
        assert(!bridge.isBytesEqual_(a, c));
        assert(!bridge.isBytesEqual_(d, e));
        assert(bridge.isBytesEqual_(d, f));

        assertFalse(bridge.isBytesEqual_(a, d));
        assertFalse(bridge.isBytesEqual_(a, hex""));
    }

    function testBytesEqualEdge() public view {
        bytes memory a31 = hex"689059e65a478c636524643c3141f00fe3c27b802580fc12a3da9bc373596b";
        bytes memory b31 = hex"689059e65a478c636524643c3141f00fe3c27b802580fc12a3da9bc373596b";
        bytes memory c31 = hex"689059e65a478c636524643c3141f00fe3c27b802580fc12a3da9bc373596a";
        assert(bridge.isBytesEqual_(a31, b31));
        assert(!bridge.isBytesEqual_(a31, c31));

        bytes memory a32 = hex"689059e65a478c636524643c3141f00fe3c27b802580fc12a3da9bc373596b5c";
        bytes memory b32 = hex"689059e65a478c636524643c3141f00fe3c27b802580fc12a3da9bc373596b5c";
        bytes memory c32 = hex"689059e65a478c636524643c3141f00fe3c27b802580fc12a3da9bc373596b5a";
        assert(bridge.isBytesEqual_(a32, b32));
        assert(!bridge.isBytesEqual_(a32, c32));

        bytes memory a33 = hex"689059e65a478c636524643c3141f00fe3c27b802580fc12a3da9bc373596b5c1f";
        bytes memory b33 = hex"689059e65a478c636524643c3141f00fe3c27b802580fc12a3da9bc373596b5c1f";
        bytes memory c33 = hex"689059e65a478c636524643c3141f00fe3c27b802580fc12a3da9bc373596b5c1a";
        assert(bridge.isBytesEqual_(a33, b33));
        assert(!bridge.isBytesEqual_(a33, c33));

        assert(!bridge.isBytesEqual_(a31, a32));
        assert(!bridge.isBytesEqual_(a31, a33));
        assert(!bridge.isBytesEqual_(a32, a33));
    }

    function testBytesEqualFuzz(bytes memory a, bytes memory b) public view {
        vm.assume(a.length == b.length);
        assertEq(isKeccakEqual(a, b), bridge.isBytesEqual_(a, b));
    }

    function testBytesEqualForEqualInputsFuzz(bytes memory a) public view {
        assertEq(isKeccakEqual(a, a), bridge.isBytesEqual_(a, a));
    }

    function testSetDepositScript() public {
        vm.prank(owner);
        bridge.setDepositScript(depositScript, scriptSuffix);
        assert(bridge.isBytesEqual_(depositScript, bridge.depositScript()));
        assert(bridge.isBytesEqual_(scriptSuffix, bridge.scriptSuffix()));
    }

    function testUpgrade() public {
        address falseBridgeImpl = address(new FalseBridge());
        vm.prank(owner);
        proxyAdmin.upgrade(ITransparentUpgradeableProxy(payable(address(bridge))), falseBridgeImpl);
        assertEq(FalseBridge(address(bridge)).falseFunc(), keccak256("false"));
    }

    function testNonOwnerCannotUpgrade() public {
        address falseBridgeImpl = address(new FalseBridge());
        vm.prank(user);
        vm.expectRevert();
        proxyAdmin.upgrade(ITransparentUpgradeableProxy(payable(address(bridge))), falseBridgeImpl);
    }

    function testOwnerCanChangeAndUpgrade() public {
        address falseBridgeImpl = address(new FalseBridge());
        vm.stopPrank();
        address newOwner = makeAddr("citrea_new_owner");
        vm.prank(owner);
        proxyAdmin.transferOwnership(newOwner);
        vm.startPrank(newOwner);
        proxyAdmin.upgrade(ITransparentUpgradeableProxy(payable(address(bridge))), falseBridgeImpl);
        assertEq(FalseBridge(address(bridge)).falseFunc(), keccak256("false"));
    }

    function isKeccakEqual(bytes memory a, bytes memory b) public pure returns (bool result) {
        result = keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }

    function doDeposit() public {
        vm.startPrank(operator);
        Bridge.TransactionParams memory depositParams = Bridge.TransactionParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER, index);
        bridge.deposit(depositParams);
        vm.stopPrank();
    }
}