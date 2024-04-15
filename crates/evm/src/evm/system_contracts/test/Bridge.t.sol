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
    bytes2 flag = hex"0001";

    bytes4 version = hex"02000000";
    bytes vin = hex"01d4d6c5c94583a0505dd0c1eb64760ba2a6a391f6da3164094ed8bcac190b7d6c0000000000fdffffff";
    bytes vout = hex"0378dcf50500000000225120081bb55c845b1b14b8580a0246764d53d4aa579645c67568d8375c71f687a2ce4a01000000000000220020340a847f2a890d208f6c7a21811116134bd2b01cc1d46a999e61da195f6b8a3b4a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
    bytes4 locktime = hex"00000000";
    bytes witness = hex"0740b500164ed14931558b6f101350bd896d8ef7b5215268aec6fa97624f97d4e921f954c362dacb706875ba86280798f4a141745d09444d8f6a62483046bc1e87624025b756b973a6f96a60fde1e745765ffb5d4bfafbd3380e0044dfb0c4c59bba973d0806942a718458696f2c09f7c1a4f672479d7b8f678dff07badf546ab3d2004045d7ea88c30d6da0f4c08c808b2b72c02833a0bc1f44d901954e671e531a33e2b5919ebad1655c3df651b22591777649e60aab07b8507112df2b3da1c3ec65fd401f83b69afc860240e486af437c09949f7a9ab7a795090d3ce8a88ef3a460de56c0ed3bca888cae22e31495e1bcd22148d5185cbf05302b1d910096d18414368f400b6e7417ca7a5f3fefd221087288abbef35aa93db502bc9b32b4ce48edb666c6ea36d6a1d5fc2a78aaab61f71355b7816f7fe15bb3355c56720f7eb27d6ca8a3c3203402ede68395331e2797e1d8fd2ba951386baab32d1440252c3214e0708fe479ad20c18c593480f4f55a3fd7617c9df6e3dabc80fca5927f66d20050c82a2012be7aad2089c310c07b3c3901562a3f000c4a477fcb5ebfd362de3d07a0bff927f2911301ad2067de68f8eb816c86396802b389dedec01703d79e9910e0c846f48920a3e33dd7ad2040f1506702e400b8d1aed2de05bf776e6d7602378ab0834a7d771039454af56ead5100631401010101010101010101010101010101010101016841c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51e8bbb8cb70da9374d24ddfec9bfd8d90b89563c2a55de80fbeba57c0a2de1bce";
    bytes depositScript = hex"c3203402ede68395331e2797e1d8fd2ba951386baab32d1440252c3214e0708fe479ad20c18c593480f4f55a3fd7617c9df6e3dabc80fca5927f66d20050c82a2012be7aad2089c310c07b3c3901562a3f000c4a477fcb5ebfd362de3d07a0bff927f2911301ad2067de68f8eb816c86396802b389dedec01703d79e9910e0c846f48920a3e33dd7ad2040f1506702e400b8d1aed2de05bf776e6d7602378ab0834a7d771039454af56ead51006314";
    bytes scriptSuffix = hex"68";
    bytes intermediate_nodes = hex"0000000000000000000000000000000000000000000000000000000000000000d867753e5c6294897137132af54a90ad05cc9590f372f4ac8aae50096c7de081cfbfc52d11aa289adf40426b589cf9739b030a8b61c0ec22347ce3af642b9f52783f00e738b6e46376ca7756b4230c80c9b4b68701b81f690e00d1df24744e5d872a65c80bfd54acc25e622708cf18000b6815d000729aa880b974f2187137ea";
    uint256 index = 1;

    address receiver = address(0x0101010101010101010101010101010101010101);
    address operator = makeAddr("citrea_operator");
    address user = makeAddr("citrea_user");

    uint256 constant INITIAL_BLOCK_NUMBER = 505050;
    bytes32 witnessRoot = hex"46b8e96a9798742f3d555ad1d1b0c31a29fac5e0d133a44126a8b3ca02077ece";

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
        
        // Arbitrary blockhash as this is mock 
        bytes32 expected_blockhash = keccak256("CITREA_TEST");
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
        vm.expectRevert("wtxId already spent");
        doDeposit();
    }

    function testCannotDepositWithFalseDepositScript() public {
        // One byte different
        witness = hex"0740c7b01838a1f40585926c23293d05a7fb094a8515c517bf65b6d88037cb44616b7baf1049017c12c2dbca7508fc42c2355b9224e31412e0d1adc2a24563503226408342e65256c8eb6b74fa274bb0c953f05a106a5743f04a3ce658c94d6b7ec1255058bb9990ffbdba763383deab2ca4d003f6ded8e512349c0408e26b60235f77409d243f90d875d261a909c4303a8e83bec1230620034570da298038b7acf9bfc00a5d1e094426b092f243276181d0e674a60ac74972e1893e2970a537018df284402ec76c955ee4ffd27fe897b38c547346e13b4e3efffd08be392ca39560671141e1606f7353a2f9e9a27cd897ff783365d2bdbd4a8a61a5e5c22fdebb7a19d1bb40251ff30263cfcd1acd0e036ebfb136ec828d11b5cb604cf79dd3b90fd583b3ebdbc5e86f7487d0a8fe1c8d9219181d582fd90940e83dccc4f889e38436fbecebc320a204782be8112b0b650e275123d68c21fd41e93fca2ac6a6c84ebdbce9dc4434ad20ca567297dceae237eff0f924d9debc852f298f0c895cc88c47f8d494137c98fcad20c393c1f704c9994788ab92351b0bc9be7f953b33d40df352769c5cd2e2b050f5ad209ab5ba3ec29598206e2af5d7f56edba94bba1a0c25a4dd8319a13265c138aa67ad200c7f7bfcb9b847cfb27d809e394c4f26fdb844efc7ba8a4825663eeae08d9201ad5100631400000000000000000000000000000000000000006841c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51846f56a7983baf5a8aa4be108d12c6d06a40d1374aed6849682a4c0e2d23241d"; 
        bridge.setOperator(operator);
        vm.startPrank(operator);
        vm.expectRevert("Invalid deposit script");
        doDeposit();
    }

    function testCannotWithdrawWithInvalidAmount() public {
        // Operator makes a deposit for the `receiver` address specified in the second output of above Bitcoin txn
        bridge.setOperator(operator);
        vm.startPrank(operator);
        doDeposit();

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
        Bridge.DepositParams memory depositParams = Bridge.DepositParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER, index);
        bridge.deposit(depositParams);
    }
}
