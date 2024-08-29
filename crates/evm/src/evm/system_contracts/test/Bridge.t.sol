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
    bytes vin = hex"01045d6e5bb4944de10ef0a2b37554f9985f60e803ccb6fbb0e3e91c275cffa5d90000000000fdffffff";
    bytes vout = hex"0285c79a3b0000000022512032dd3f3e100a141cd1327bb8b40937f5835f63e6d52187c69e4ab916a533deef4a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
    bytes4 locktime = hex"00000000";
    bytes witness = hex"0340ad9864b67b23de84f58e9131c1a691f64c61140d7a0c0da4c6cb473d57479efdf831fa18e45d5129a1a51e2ff9b23033deb1ada80be24e858393760bf0b59ea64a20a9dc2892380bf8245eb7a677ab166c98514ea6c5ce7946adbf4c05afb2bfbffdac00630663697472656114010101010101010101010101010101010101010108000000003b9aca006841c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51b9aaed9558e3121f0696c8dd1ed0ad4059716c297e9a35f47f4120a350bf1e6c";
    bytes scriptPrefix = hex"4a20a9dc2892380bf8245eb7a677ab166c98514ea6c5ce7946adbf4c05afb2bfbffdac00630663697472656114";
    bytes scriptSuffix = hex"08000000003b9aca0068";
    bytes intermediate_nodes = hex"2c22f394f47ac846fa34c928a9336050a94c076a3dcd55b2a5a8edd6f557d7fe725181db80d39bf8351687f5a59e523d3d8754ecbac1775abc3488386b8e57cebbeb1cad0ef9d46e3e92b573a92589f33245b19267d811de09dbb8b437aea901ce0dc15ef08b62651098aebae5033457a9ab75297fa25f8af9f522a2afbbeaae";
    uint256 index = 8;

    address constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);
    address receiver = address(0x0101010101010101010101010101010101010101);
    address user = makeAddr("citrea_user");
    address owner = makeAddr("citrea_owner");
    address operator;
    uint256 constant INITIAL_BLOCK_NUMBER = 1;
    bytes32 witnessRoot = hex"262b8d9b4572608d1a45d56e70a84aa62296051a11991079fdd50db2820ef98c";
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
        bridge.initialize(scriptPrefix, scriptSuffix, 10 ether);
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

    function testDeclareWithdrawFiller() public {
        vm.startPrank(user);
        vm.deal(address(user), DEPOSIT_AMOUNT);
        bytes32 txId = hex"3ed5653492eb5bf3124280e06d3d8bd1195fe0e8711fabefec8a057d0b6e8326";
        bytes4 outputId = hex"00000000";
        bridge.withdraw{value: DEPOSIT_AMOUNT}(txId, outputId);
        assertEq(user.balance, 0);
        vm.stopPrank();
        vin = hex"043ed5653492eb5bf3124280e06d3d8bd1195fe0e8711fabefec8a057d0b6e83260000000000fdffffff9914c1e42a991818504847ba15aac11c6105152a7059c5b964e8ef595e99b0f70100000000fdffffffd4e6478683813dd8ca4e1131d4e0b83cebe683db2de07e79bdaec87901d24c1c0100000000fdffffffaa6a1d8b512d251dd974bf2b5401a78915dc91a92d3cbb78d5de9d1410cc504e0100000000fdffffff";
        vout = hex"0300ca9a3b000000002251204f78821f08f119333f981396ec5941b9f67a05c5302ecb7031861a879bbb0fbbccdf780c0100000022512064f89766e0e03d3399bb515e9c925d798280852b45a3497e1570b3ede3a0178b0000000000000000036a0100";
        witness = hex"014186bf8839ac35b0e9dcf5db2af4bd0343b561c1ebb585db6f73b15f54262945dbc0a4715733433b1d1809e747c203d2d4024876c5bafcd51ca23bc356b80b009283014034ace8e8ff56733a161f0bb6fdf12eb7868fcf6eb1e22940941e2a54526de776c3ba38b32fe3b11f8d861705dab2d1b21992539f93960cce729830e40d0bf3cd0140f3e91dc215637462c5454c22db25b287e9e81cfc6f323b4ce5ab2f7cfa844ac967224016a46a9efd1e520734a8ff96ba3898a9d628bec0b7f671dfe8a767589f014007e19ba13396ef6c15099062ec72b53b446bda9f3e3fc3ea789be8e2d7abc8ccb5fc42e5c48c7a4a87734de375fdc680fb2b6819e09040ced8d87f143eb94946";
        intermediate_nodes = hex"07183ca6716011765b6d06e60849938f6d05e3411c5dc9ce03015c9d4da19d214e4de3bc8373f646cf973b9e8a26b689a229ee1ec94f8575fb4ee9135fa9eff246412f1a24b3d2de50bce07e220bfecd637de25645e9df987af6d73267e108313ac8881c14a24956a470afa77f7b67b1f60d2c8b297c0a7bb92334e32e9a8980";
        index = 4;
        vm.prank(SYSTEM_CALLER);
        Bridge.TransactionParams memory withdrawTp = Bridge.TransactionParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER, index);
        bridge.declareWithdrawFiller(withdrawTp, 0, 0);
        require(bridge.withdrawFillers(0) == 1); // 1-indexed first operator
    }

    function testCannotMarkDeclaredOperatorAsMalicious() public {
        testDeclareWithdrawFiller();
        vin = hex"01d222fc4a6d204c3f3a2cbffdd16adc4bfd79eb78fd7f10c4ee6d32387d5b71ec0000000000fdffffff";
        vout = hex"032584010000000000225120d1818e236695de6f9562a48a549efeab87b0c07fd196d7d9451507ee9a3b84ec4a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600000000000000000236a214a3cda034428e2f1af6f9c7da8f77d1e7b5cb672bbec62895e1b4b949372ef3900";
        witness = hex"0440c9146dc306e3daec54e99e6ea75a6aaad6b3c21ab71460ecf9fd2c6be6e6867eda1f5dbe646c0ad0ec5579f0cfc4a78fbe411e687c5cc2e8544a859ca570c18040a8e3ef09f9aae766746a914e6e10ac8d54257a1a28ad5dc1cfea32ac3737c5ca510d39f79d799a0343cccaedf7a4266dea890b221ce758eefe1d901767150c7d4420a9dc2892380bf8245eb7a677ab166c98514ea6c5ce7946adbf4c05afb2bfbffdad204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaac21c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51";
        intermediate_nodes = hex"bcc6f64a54c4a4bb4742a268d36f9d51b662df213e0348b6553836c1c57802a3ef23022f44b5a2c53d00f25e0051bb594b1b8ca5745f3856ea2fa6b0be8e1e43bbeb1cad0ef9d46e3e92b573a92589f33245b19267d811de09dbb8b437aea901ce0dc15ef08b62651098aebae5033457a9ab75297fa25f8af9f522a2afbbeaae";
        index = 10;
        vm.prank(SYSTEM_CALLER);
        Bridge.TransactionParams memory kickoff2Tp = Bridge.TransactionParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER, index);
        vm.expectRevert("Operator is not malicious");
        bridge.markMaliciousOperator(kickoff2Tp);
    }

    function testMarkMaliciousOperator() public {
        vin = hex"01d222fc4a6d204c3f3a2cbffdd16adc4bfd79eb78fd7f10c4ee6d32387d5b71ec0000000000fdffffff";
        vout = hex"032584010000000000225120d1818e236695de6f9562a48a549efeab87b0c07fd196d7d9451507ee9a3b84ec4a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600000000000000000236a214a3cda034428e2f1af6f9c7da8f77d1e7b5cb672bbec62895e1b4b949372ef3900";
        witness = hex"0440c9146dc306e3daec54e99e6ea75a6aaad6b3c21ab71460ecf9fd2c6be6e6867eda1f5dbe646c0ad0ec5579f0cfc4a78fbe411e687c5cc2e8544a859ca570c18040a8e3ef09f9aae766746a914e6e10ac8d54257a1a28ad5dc1cfea32ac3737c5ca510d39f79d799a0343cccaedf7a4266dea890b221ce758eefe1d901767150c7d4420a9dc2892380bf8245eb7a677ab166c98514ea6c5ce7946adbf4c05afb2bfbffdad204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaac21c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51";
        intermediate_nodes = hex"bcc6f64a54c4a4bb4742a268d36f9d51b662df213e0348b6553836c1c57802a3ef23022f44b5a2c53d00f25e0051bb594b1b8ca5745f3856ea2fa6b0be8e1e43bbeb1cad0ef9d46e3e92b573a92589f33245b19267d811de09dbb8b437aea901ce0dc15ef08b62651098aebae5033457a9ab75297fa25f8af9f522a2afbbeaae";
        index = 10;
        vm.prank(SYSTEM_CALLER);
        Bridge.TransactionParams memory kickoff2Tp = Bridge.TransactionParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER, index);
        bridge.markMaliciousOperator(kickoff2Tp);
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
        witness = hex"03409dd5769e2cbd0c8eff9d9e059140d68d7df6317ecc7bc357cbf19c8b23a21f4a16f2840a3284cfb697c3e8abbd6062f67e4b8bae686007740e22480baba74cbf4a20a9dc2892380bf8245eb7a677ab166c98514ea6c5ce7946adbf4c05afb2bfbffdac00630663697472656115010101010101010101010101010101010101010108000000003b9aca006841c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51131a3022638eec69204e3337e4298c7df7ed343b11ac49ae2d0fbfb328860f9e";
        witnessRoot = hex"6174b0fdc4025fe6c7e45ef62d6c43f692342a3e7dc8d2f6073c6cc813aa2cb4";
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
        bridge.initialize(scriptPrefix, scriptSuffix, 5);
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
        bridge.setDepositScript(scriptPrefix, scriptSuffix);
        assert(bridge.isBytesEqual_(scriptPrefix, bridge.scriptPrefix()));
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