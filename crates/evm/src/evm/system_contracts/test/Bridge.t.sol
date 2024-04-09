// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/Bridge.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";

// !!! WARNINGS:
// !!! - Update `testDepositThenWithdraw` and `testBatchWithdraw` with proper testing of withdrawal tree root if this goes to production
// !!! - Write fuzz tests for deposit and withdraw actions with random Bitcoin txns if this goes to production

contract BridgeHarness is Bridge {
    constructor(uint32 _levels) Bridge(_levels) {}
    // Overriding in harness is needed as internal functions are not accessible in the test
    function isBytesEqual_(bytes memory a, bytes memory b) public pure returns (bool result) {
        result = super.isBytesEqual(a, b);
    }
}

contract BridgeTest is Test {
    uint256 constant DEPOSIT_AMOUNT = 1 ether;
    BridgeHarness public bridge;
    bytes4 version = hex"02000000";
    bytes2 flag = hex"0001";
    bytes vin = hex"0197d91aeca70ec28f98b58510a22d93f0184549301f050b2a7841076a320693a10000000000fdffffff";
    bytes vout = hex"0378dcf505000000002251209602168495f14a8c1919654fac3070a1e4332c341d10a9c760d76ee9d4eb32844a01000000000000220020d664b02f11a411580603be300ec7a7e8e08bf24a5ace393e3290c54858e939bd4a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
    bytes depositScript = hex"074037090b5908403c219b6bb006afc47fcd170ad97deb1c5e1559bca290f3a2e25ef4debdb76dcdbe3e6a7a2199c975dc60021af24a93b269cf88c195df04ea68744044582d33a8140905df010c8e28c5174019d215763d4498e26f5e55ddc3a85693cd9669f2ca81f03c6f296e54d6b734796e432e0c04b3761d0c26eea892842b9e40911ac3079b5d1bef5d5042346bba271332484566b6904727f90faa6c5be622e085744904f055cda49d6d2147e382e1642454aa8c6e0191e25cd5a167e8a795a640cc5b20dcb483fcb937f77d727a3ffd73f372cf935f8e4c1455708803939dd37fb9e34714673bcc3500b8dc9d453efc4feda33de1fb71ee5827d0ca0b2920af80405ea037703cc77370e2c826bc6923d17820923bb305e2b59f6bb030edce0e33abf789ea32cb955b9acf8ac56790798ca319b8cf45392b48ac42878fb24cb81e1fc3208fe8f6f24f0fceb83025dd76ca4637acbbbce43f3c317ae7c879cc32057ea614ad20317c6914342dfeae1298628887d09ca80ec8179e77e934c6186a6c6ed7911b3aad20d3383121537e1f2ee45f82d96fd39d5424bd1b9202b2f86887de3500d09407bead205f34640f59e113fc9ca86d32c42d760faef29706fd313a0c0281bfc7d4ebc24bad20a2ea14069c084ef6f2ea114ae5e717479f75ca4bb3f53be2e4f0bbf7225f51d0ad51006314";
    bytes scriptSuffix = hex"68";
    bytes witness = hex"074037090b5908403c219b6bb006afc47fcd170ad97deb1c5e1559bca290f3a2e25ef4debdb76dcdbe3e6a7a2199c975dc60021af24a93b269cf88c195df04ea68744044582d33a8140905df010c8e28c5174019d215763d4498e26f5e55ddc3a85693cd9669f2ca81f03c6f296e54d6b734796e432e0c04b3761d0c26eea892842b9e40911ac3079b5d1bef5d5042346bba271332484566b6904727f90faa6c5be622e085744904f055cda49d6d2147e382e1642454aa8c6e0191e25cd5a167e8a795a640cc5b20dcb483fcb937f77d727a3ffd73f372cf935f8e4c1455708803939dd37fb9e34714673bcc3500b8dc9d453efc4feda33de1fb71ee5827d0ca0b2920af80405ea037703cc77370e2c826bc6923d17820923bb305e2b59f6bb030edce0e33abf789ea32cb955b9acf8ac56790798ca319b8cf45392b48ac42878fb24cb81e1fc3208fe8f6f24f0fceb83025dd76ca4637acbbbce43f3c317ae7c879cc32057ea614ad20317c6914342dfeae1298628887d09ca80ec8179e77e934c6186a6c6ed7911b3aad20d3383121537e1f2ee45f82d96fd39d5424bd1b9202b2f86887de3500d09407bead205f34640f59e113fc9ca86d32c42d760faef29706fd313a0c0281bfc7d4ebc24bad20a2ea14069c084ef6f2ea114ae5e717479f75ca4bb3f53be2e4f0bbf7225f51d0ad5100631400000000000000000000000000000000000000006841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51a9b42aabe8e3f300e73ca8991cb4213762eec2a66536149da8b00eca98b5daeb";
    bytes4 locktime = hex"00000000";

    // TODO: CHANGE THESE
    bytes intermediate_nodes = hex"b2fd785590896305ab9c3dd8453acfdb6d3d0538ce72f10e9e720e5c39ba1aa61918d0dd24910a182354cbf2f9e1c85e56e176afdc0763f04186f367d0d1434e936800c1e088f80a692cc8af3c6d3afa7f3d6fcead06b53739de44e67fce59533dffa19f80d5a8a0c9698bb096ae937d4a9a31640cf40da4c923e8833448de33";    
    bytes block_header = hex"00000020bc9079764fe41a13327a9f1b99931b18b34d60d3947f956949eec5c1af5cb80d0a76a7d6a942436f382e259c20d0c5fee06b12799b491683f9c418311e83e224fe28d765ffff7f2001000000";
    uint index = 1;

    address operator = makeAddr("citrea_operator");
    address user = makeAddr("citrea_user");

    uint256 constant INITIAL_BLOCK_NUMBER = 505050;
    // TODO: Change this
    bytes32 witnessRoot = bytes32(keccak256("CITREA"));

    function setUp() public {
        bridge = new BridgeHarness(31);
        vm.deal(address(bridge), 21_000_000 ether);
        address block_hash_list_impl = address(new L1BlockHashList());
        L1BlockHashList l1BlockHashList = bridge.BLOCK_HASH_LIST();
        vm.etch(address(l1BlockHashList), block_hash_list_impl.code);

        address self = address(this);
        vm.startPrank(address(0));
        l1BlockHashList.transferOwnership(self);
        vm.stopPrank();
        l1BlockHashList.acceptOwnership();

        l1BlockHashList.initializeBlockNumber(INITIAL_BLOCK_NUMBER);
        // TODO: Change this 
        bytes32 expected_blockhash = hex"b25d57f9acbf22e533b0963b47d91b11bdef9da9591002b1ef4e3ef856aec80e";
        l1BlockHashList.setBlockInfo(expected_blockhash, witnessRoot);

        bridge.setDepositScript(depositScript, scriptSuffix, 5);
    }

    function testZeros() public view {
        bytes32 zero = bridge.ZERO_VALUE();
        assertEq(zero, bridge.zeros(0));
        assertEq(zero, keccak256("CITREA"));
        for (uint32 i = 1; i < 33; i++) {
            zero = bridge.hashLeftRight(zero, zero);
            assertEq(zero, bridge.zeros(i));
        }
    }

    function testDeposit() public {
        // Operator makes a deposit for the `receiver` address specified in the second output of above Bitcoin txn
        bridge.setOperator(operator);
        vm.startPrank(operator);
        doDeposit();

        bytes memory output2 = BTCUtils.extractOutputAtIndex(vout, 1);
        bytes memory output2_ext = BTCUtils.extractOpReturnData(output2);
        address receiver = address(bytes20(output2_ext));

        // Assert if asset transferred
        assertEq(receiver.balance, DEPOSIT_AMOUNT);
        vm.stopPrank();
    }

    // TODO: Replace the logic of testing the root of withdrawal tree in a more proper manner if this goes into production
    function testDepositThenWithdraw() public {
        // Operator makes a deposit for the `receiver` address specified in the second output of above Bitcoin txn
        bridge.setOperator(operator);
        vm.startPrank(operator);
        doDeposit();

        bytes memory output2 = BTCUtils.extractOutputAtIndex(vout, 1);
        bytes memory output2_ext = BTCUtils.extractOpReturnData(output2);
        address receiver = address(bytes20(output2_ext));

        // Assert if transferred
        assertEq(receiver.balance, DEPOSIT_AMOUNT);
        vm.stopPrank();

        // Assert if receiver can withdraw
        vm.startPrank(receiver);
        bytes32 bitcoin_address = hex"1234"; // Dummy Bitcoin address
        bytes32 withdrawal_root = bridge.getRootWithdrawalTree();
        bridge.withdraw{value: DEPOSIT_AMOUNT}(bitcoin_address);
        bytes32 updated_withdrawal_root = bridge.getRootWithdrawalTree();
        
        // Assert if tokens are burned from receiver
        assertEq(receiver.balance, 0);

        // Assert if withdrawal root is updated
        assert(withdrawal_root != updated_withdrawal_root);
        bytes32 expected_root = 0x574330cc8e4db82e36b5daf43915ccb2bf785ac361c3882cc4cdd2a13183af99; // Calculate with another implementation of merkle tree
        assertEq(updated_withdrawal_root, expected_root);

        vm.stopPrank();
    }

    function testBatchWithdraw() public {
        vm.startPrank(user);
        vm.deal(address(user), 10 ether);
        bytes32[] memory btc_addresses = new bytes32[](10);
        for (uint i = 0; i < 10; i++) {
            btc_addresses[i] = bytes32(abi.encodePacked(i));
        }
        bytes32 withdrawal_root = bridge.getRootWithdrawalTree();
        bridge.batchWithdraw{value: 10 ether}(btc_addresses);
        bytes32 updated_withdrawal_root = bridge.getRootWithdrawalTree();
        assert(withdrawal_root != updated_withdrawal_root);
        assertEq(user.balance, 0);
    }

    function testCannotBatchWithdrawWithWrongValue() public {
        vm.startPrank(user);
        vm.deal(address(user), 10 ether);
        bytes32[] memory btc_addresses = new bytes32[](10);
        for (uint i = 0; i < 10; i++) {
            btc_addresses[i] = bytes32(abi.encodePacked(i));
        }
        vm.expectRevert("Invalid withdraw amount");
        bridge.batchWithdraw{value: 9 ether}(btc_addresses);
    }

    function testCannotDoubleDepositWithSameTx() public {
        bridge.setOperator(operator);
        vm.startPrank(operator);
        doDeposit();
        vm.expectRevert("txId already spent");
        doDeposit();
    }

    function testCannotDepositWithFalseProof() public {
        vin = hex"1234";
        bridge.setOperator(operator);
        vm.startPrank(operator);
        vm.expectRevert("SPV Verification failed.");
        doDeposit();
    }

    function testCannotDepositWithFalseBlockHash() public {
        block_header = hex"1234";
        bridge.setOperator(operator);
        vm.startPrank(operator);
        vm.expectRevert("Incorrect block hash");
        doDeposit();
    }

    function testCannotWithdrawWithInvalidAmount() public {
        // Operator makes a deposit for the `receiver` address specified in the second output of above Bitcoin txn
        bridge.setOperator(operator);
        vm.startPrank(operator);
        doDeposit();

        bytes memory output2 = BTCUtils.extractOutputAtIndex(vout, 1);
        bytes memory output2_ext = BTCUtils.extractOpReturnData(output2);
        address receiver = address(bytes20(output2_ext));

        // Assert if transferred
        assertEq(receiver.balance, DEPOSIT_AMOUNT);
        vm.stopPrank();

        // Assert if receiver cannot withdraw with invalid amount
        vm.startPrank(receiver);
        vm.expectRevert("Invalid withdraw amount");
        bridge.withdraw{value: DEPOSIT_AMOUNT - 1}(hex"1234");
        vm.stopPrank();
    }

    function testNonOperatorCannotDeposit() public {
        vm.expectRevert("caller is not the operator");
        doDeposit();
    }

    function testCannotSetOperatorIfNotOwner() public {
        vm.startPrank(user);
        vm.expectRevert();
        bridge.setOperator(operator);
    }

    function testBytesEqual() public {
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

        vm.expectRevert();
        bridge.isBytesEqual_(a, d);

        vm.expectRevert();
        bridge.isBytesEqual_(a, hex"");
    }

    function testBytesEqualFuzz(bytes memory a, bytes memory b) public view {
        vm.assume(a.length == b.length);
        assertEq(isKeccakEqual(a, b), bridge.isBytesEqual_(a, b));
    }

    function testBytesEqualForEqualInputsFuzz(bytes memory a) public view {
        assertEq(isKeccakEqual(a, a), bridge.isBytesEqual_(a, a));
    }

    function testSetDepositScript() public {
        bridge.setDepositScript(depositScript, scriptSuffix, 5);
        assert(bridge.isBytesEqual_(depositScript, bridge.depositScript()));
        assert(bridge.isBytesEqual_(scriptSuffix, bridge.scriptSuffix()));
        assertEq(5, bridge.verifierCount());
    }

    function isKeccakEqual(bytes memory a, bytes memory b) public pure returns (bool result) {
        result = keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }

    function doDeposit() public {
        Bridge.DepositParams memory depositParams = Bridge.DepositParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, block_header, INITIAL_BLOCK_NUMBER, index);
        bridge.deposit(depositParams);
    }
}
