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
    bytes vin = hex"01e2cb8b8c15fee29eb9cee7246ce582f412267f36b01039eb862ce3518afb95bb0100000000fdffffff";
    bytes vout = hex"0285c79a3b00000000225120984c99c0ed8f91a0e9f70c1ab451e9e78107ecf73a12500ecd0760bea016cdfb4a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
    bytes4 locktime = hex"00000000";
    bytes witness = hex"0340abce0ec04f05a22e2bf811b824d91fda4ff6ec94f055d5715cf4384036dd157392cfab47ee808e2ddf97650e420dc848de08699f9184e2ee35da77ed05c9276e4a207c4803421956db53eed29ee45bddbe60d16e66560f918a94270ea5272b2b4e90ac00630663697472656114010101010101010101010101010101010101010108000000003b9aca006841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51b540e929d1a8f60137e49aaf57049ce593639353871a9ce9cb176070827a09dd";
    bytes depositPrefix = hex"4a207c4803421956db53eed29ee45bddbe60d16e66560f918a94270ea5272b2b4e90ac00630663697472656114";
    bytes depositSuffix = hex"08000000003b9aca0068";
    bytes intermediate_nodes = hex"00000000000000000000000000000000000000000000000000000000000000005d0b2d694672fc17e41b10278477709b500fed59aae67dba417d442e2c7f4c6900a1c64882d54993fc008ab1e9ae150a78cc08aac6bbbb41db77f55134cb6198";
    uint256 index = 1;

    address constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);
    address receiver = address(0x0101010101010101010101010101010101010101);
    address user = makeAddr("citrea_user");
    address owner = makeAddr("citrea_owner");
    address operator;
    uint256 constant INITIAL_BLOCK_NUMBER = 1;
    bytes32 witnessRoot = hex"142a6fc911b3091261ef52d2a50bc0f25797d73da457a7e51b6a81b51519aa1e";
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
        bridge.initialize(depositPrefix, depositSuffix, 10 ether);
        vm.deal(address(bridge), 21_000_000 ether);
        address lightClient_impl = address(new BitcoinLightClient());
        bitcoinLightClient = bridge.LIGHT_CLIENT();
        vm.etch(address(bitcoinLightClient), lightClient_impl.code);

        vm.startPrank(SYSTEM_CALLER);
        bitcoinLightClient.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        // Arbitrary blockhash as this is mock
        bitcoinLightClient.setBlockInfo(mockBlockhash, witnessRoot, 3);
        vm.stopPrank();

        operator = bridge.operator();
    }

    function testDeposit() public {
        doDeposit();
        // Assert if asset transferred
        assertEq(receiver.balance, DEPOSIT_AMOUNT);
        assertTrue(bridge.processedTxIds(hex"84b9aae7426412e069dfd5fc513e782f6622e3afb11909d27796444707379ac0"));
        assertEq(bridge.depositTxIds(0), hex"84b9aae7426412e069dfd5fc513e782f6622e3afb11909d27796444707379ac0");
    }

    // TODO: Replace the logic of testing the root of withdrawal tree in a more proper manner if this goes into production
    function testDepositThenWithdraw() public {
        doDeposit();
        // Assert if transferred
        assertEq(receiver.balance, DEPOSIT_AMOUNT);

        // Assert if receiver can withdraw
        vm.startPrank(receiver);
        bytes32 txId = hex"1234"; // Dummy txId
        bytes4 outputId = hex"01"; // Dummy outputId
        uint256 withdrawalCount = bridge.getWithdrawalCount();
        bridge.withdraw{value: DEPOSIT_AMOUNT}(txId, outputId);

        // Assert if withdrawal address is stored properly
        (bytes32 _txId, bytes4 _outputId) = bridge.withdrawalUTXOs(withdrawalCount);
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
        bytes4[] memory output_ids = new bytes4[](10);
        for (uint i = 0; i < 10; i++) {
            btc_addresses[i] = bytes32(abi.encodePacked(i));
            output_ids[i] = bytes4(uint32(i));
        }
        
        bridge.batchWithdraw{value: DEPOSIT_AMOUNT * 10}(btc_addresses, output_ids);
        

        for (uint i = 0; i < 10; i++) {
            (bytes32 _txId, bytes4 _outputId) = bridge.withdrawalUTXOs(i);
            assertEq(_txId, btc_addresses[i]);
            assertEq(_outputId, output_ids[i]);
        }
        
        assertEq(user.balance, 0);
    }

    function testCannotBatchWithdrawWithWrongValue() public {
        vm.startPrank(user);
        vm.deal(address(user), 10 ether);
        bytes32[] memory btc_addresses = new bytes32[](10);
        bytes4[] memory output_ids = new bytes4[](10);
        for (uint i = 0; i < 10; i++) {
            btc_addresses[i] = bytes32(abi.encodePacked(i));
            output_ids[i] = bytes4(uint32(i));
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
        witness = hex"0340abce0ec04f05a22e2bf811b824d91fda4ff6ec94f055d5715cf4384036dd157392cfab47ee808e2ddf97650e420dc848de08699f9184e2ee35da77ed05c9276e4a207c4803421956db53eed29ee45bddbe60d16e66560f918a94270ea5272b2b4e90ac00630663697472656115010101010101010101010101010101010101010108000000003b9aca006841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51b540e929d1a8f60137e49aaf57049ce593639353871a9ce9cb176070827a09dd";
        witnessRoot = hex"af3827c2b44a695e5306a643f6029b68c350f9907cdf7131ef44a00d6bdee480";
        index = 0;
        intermediate_nodes = hex"";
        vm.startPrank(SYSTEM_CALLER);
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_2"), witnessRoot, 0);
        
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
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_2"), witnessRoot, 3);

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
        bridge.withdraw{value: DEPOSIT_AMOUNT - 1}(hex"1234", hex"01");
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
        bridge.initialize(depositPrefix, depositSuffix, 5);
    }

    function testCanChangeOperatorAndDeposit() public {
        vm.prank(owner);
        bridge.setOperator(user);
        operator = user;
        vm.stopPrank();
        doDeposit();
    }

    function testReplaceDeposit() public {
        vm.startPrank(operator);
        version = hex"03000000";
        vin = hex"0161d6a81afeee162b02263453162a43c3d0874264fae4fb8325ce0830a22d057d0000000000fdffffff";
        vout = hex"0210c99a3b0000000022512040b87e69e03b5535637a6fcc3ee4fee978e57944261c06b71c88a47d2d61e1b3f0000000000000000451024e73";
        witness = hex"0340f70c6ba17da3a8ba5b30495f869c537190ba49c708f6b8cf1a0425a4a4ffef5daabae4115e5b48ec5f65ae78245180285a14f231a4b3ecc8cb52611876c962e24a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114010101010101010101010101010101010101010108000000003b9aca006841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de5162e2acaa4eb5dcc1d4bfb32d9e12d444861378d4a2ccfd7d8ba97d4970be096b";
        intermediate_nodes = hex"0000000000000000000000000000000000000000000000000000000000000000a8d5764cf42bb21ec583d97fa0160e3969abf6d64790ceb25706cb97b8f8f96e1f1aac337ed626086645c4556722da89c4cee3757944b650aa383ab600dbd898";
        witnessRoot = hex"b1701bed33c8fe60fd755c939ad857a6cc41299249f46ddea25b3b06cc70d793";
        index = 1;
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_2"), witnessRoot, 3);
        vm.stopPrank();
        vm.startPrank(owner);
        bridge.setDepositScript(hex"4a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114", hex"");
        bridge.setReplaceScript(hex"54203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630d6369747265615265706c61636520", hex"");
        vm.stopPrank();
        vm.startPrank(operator);
        Bridge.TransactionParams memory depositToBeReplacedParams = Bridge.TransactionParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER + 1, index);
        bridge.deposit(depositToBeReplacedParams);
        vin = hex"016712f7c7641cacf70b1549b346e08576af09e0a2ef7b09d3d40aaefa207786ab0000000000fdffffff";
        vout = hex"0210c99a3b0000000022512040b87e69e03b5535637a6fcc3ee4fee978e57944261c06b71c88a47d2d61e1b3f0000000000000000451024e73";
        witness = hex"034077b3ac411ef95e90398e54686a7fa0a4d0d78ccc9da62befd62250254245a435fbfca5a33d351feb45c5479df126a8828446a68b6d1bc9bd38bdab712a78fedf54203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630d6369747265615265706c6163652017cec92a58d987380ae223d4a991199b3b970e493b1c67defd2d4c67ecc4e7086821c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51";
        intermediate_nodes =hex"0000000000000000000000000000000000000000000000000000000000000000069b3f62c3d1da9edc47c280146694dc1a267ef6f27d36bde7f2c6c6c9beed4f";
        witnessRoot = hex"72ae33ada5c13b2779f3b626e2d3b02c425e6e0f1fce223f8b84edf10a0337a0";
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_3"), witnessRoot, 2);
        Bridge.TransactionParams memory replaceParams = Bridge.TransactionParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER + 2, index);
        assertEq(bridge.depositTxIds(0), hex"17cec92a58d987380ae223d4a991199b3b970e493b1c67defd2d4c67ecc4e708");
        bridge.replaceDeposit(replaceParams, 0);
        assertEq(bridge.depositTxIds(0), hex"4bb8086aabf03a596218fa99170ce39393c9d3dc7dd9949f417265f246569f10");
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
        bridge.setDepositScript(depositPrefix, depositSuffix);
        assert(bridge.isBytesEqual_(depositPrefix, bridge.depositPrefix()));
        assert(bridge.isBytesEqual_(depositSuffix, bridge.depositSuffix()));
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