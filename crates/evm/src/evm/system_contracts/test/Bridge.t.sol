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
    bytes vin = hex"01335d4a3454d976220232738ca03a7f3456f2e31625b31ae484696d2669083b720000000000fdffffff";
    bytes vout = hex"03c2ddf50500000000225120fc6eb6fa4fd4ed1e8519a7edfa171eddcedfbd0e0be49b5e531ef36e7e66eb050000000000000000166a14d5463b64bb3ecd7501283145600b763c3137b4d04a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
    bytes4 locktime = hex"00000000";
    bytes intermediate_nodes = hex"b2fd785590896305ab9c3dd8453acfdb6d3d0538ce72f10e9e720e5c39ba1aa61918d0dd24910a182354cbf2f9e1c85e56e176afdc0763f04186f367d0d1434e936800c1e088f80a692cc8af3c6d3afa7f3d6fcead06b53739de44e67fce59533dffa19f80d5a8a0c9698bb096ae937d4a9a31640cf40da4c923e8833448de33";    
    bytes block_header = hex"00000020bc9079764fe41a13327a9f1b99931b18b34d60d3947f956949eec5c1af5cb80d0a76a7d6a942436f382e259c20d0c5fee06b12799b491683f9c418311e83e224fe28d765ffff7f2001000000";
    uint index = 11;

    address operator = makeAddr("citrea_operator");
    address user = makeAddr("citrea_user");

    uint256 constant INITIAL_BLOCK_NUMBER = 505050;
    bytes32 randomMerkleRoot = bytes32(keccak256("CITREA"));

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
        bytes32 expected_blockhash = hex"b25d57f9acbf22e533b0963b47d91b11bdef9da9591002b1ef4e3ef856aec80e";
        l1BlockHashList.setBlockInfo(expected_blockhash, randomMerkleRoot);
    }

    function testZeros() public {
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
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, INITIAL_BLOCK_NUMBER, index);

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
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, INITIAL_BLOCK_NUMBER, index);

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
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, INITIAL_BLOCK_NUMBER, index);
        vm.expectRevert("txId already spent");
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, INITIAL_BLOCK_NUMBER, index);
    }

    function testCannotDepositWithFalseProof() public {
        vin = hex"1234";
        bridge.setOperator(operator);
        vm.startPrank(operator);
        vm.expectRevert("SPV Verification failed.");
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, INITIAL_BLOCK_NUMBER, index);
    }

    function testCannotDepositWithFalseBlockHash() public {
        block_header = hex"1234";
        bridge.setOperator(operator);
        vm.startPrank(operator);
        vm.expectRevert("Incorrect block hash");
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, INITIAL_BLOCK_NUMBER, index);
    }

    function testCannotWithdrawWithInvalidAmount() public {
        // Operator makes a deposit for the `receiver` address specified in the second output of above Bitcoin txn
        bridge.setOperator(operator);
        vm.startPrank(operator);
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, INITIAL_BLOCK_NUMBER, index);

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
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, INITIAL_BLOCK_NUMBER, index);
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

    function testBytesEqualFuzz(bytes memory a, bytes memory b) public {
        vm.assume(a.length == b.length);
        assertEq(isKeccakEqual(a, b), bridge.isBytesEqual_(a, b));
    }

    function testBytesEqualForEqualInputsFuzz(bytes memory a) public {
        assertEq(isKeccakEqual(a, a), bridge.isBytesEqual_(a, a));
    }

    function testSetDepositTxOut0() public {
        bytes memory depositTxOut0 = hex"1234";
        bridge.setDepositTxOut0(depositTxOut0);
        assert(bridge.isBytesEqual_(depositTxOut0, bridge.DEPOSIT_TXOUT_0()));
    }

    function isKeccakEqual(bytes memory a, bytes memory b) public pure returns (bool result) {
        result = keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }

}
