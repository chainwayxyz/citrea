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
    uint256 constant DEPOSIT_AMOUNT = 0.01 ether;
    BridgeHarness public bridge = BridgeHarness(address(0x3100000000000000000000000000000000000002));
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

    address constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);
    address receiver = address(0x0101010101010101010101010101010101010101);
    address user = makeAddr("citrea_user");
    address owner = makeAddr("citrea_owner");
    address operator;
    uint256 constant INITIAL_BLOCK_NUMBER = 505050;
    bytes32 witnessRoot = hex"46b8e96a9798742f3d555ad1d1b0c31a29fac5e0d133a44126a8b3ca02077ece";
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
        bridge.initialize(depositScript, scriptSuffix, 5);
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
        bytes32 bitcoin_address = hex"1234"; // Dummy Bitcoin address
        uint256 withdrawalCount = bridge.getWithdrawalCount();
        bridge.withdraw{value: DEPOSIT_AMOUNT}(bitcoin_address);

        // Assert if withdrawal address is stored properly
        assertEq(bridge.withdrawalAddrs(withdrawalCount), bitcoin_address);
        
        // Assert if tokens are burned from receiver
        assertEq(receiver.balance, 0);


        vm.stopPrank();
    }

    function testBatchWithdraw() public {
        vm.startPrank(user);
        vm.deal(address(user), 0.1 ether);
        bytes32[] memory btc_addresses = new bytes32[](10);
        for (uint i = 0; i < 10; i++) {
            btc_addresses[i] = bytes32(abi.encodePacked(i));
        }
        
        bridge.batchWithdraw{value: 0.1 ether}(btc_addresses);
        

        for (uint i = 0; i < 10; i++) {
            assertEq(bridge.withdrawalAddrs(i), btc_addresses[i]);
        }
        
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
        doDeposit();
        vm.expectRevert("wtxId already spent");
        doDeposit();
    }

    function testCannotDepositWithFalseDepositScript() public {
        // False witness
        version = hex"02000000";
        vin = hex"01c12c5ac7555c4af5c170ab2bd2d3c7bf22157cd93b7f4a728aa8632d63b3f6cd0100000000fdffffff";
        vout = hex"0378dcf505000000002251205a7dc72cac5b5f3fc1ea4d0f0d7859b1936ee884901016fc4b749eb5b9742c2e4a01000000000000220020340a847f2a890d208f6c7a21811116134bd2b01cc1d46a999e61da195f6b8a3b4a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
        locktime = hex"00000000";
        witness = hex"0740b0e44fc2baaa22d26b78f74b64fe5e04ceb9726422a471be287b5aa9b81644f4e15519da0a887acb708c6bec13cfa2f45fc958fcb7ee0c11b7b653ad0dbc518f40324f831d9e2b8563ec6a5ac14ccf1c24494410493c5373b31dcabbf84542a6b233ba5ae8f24f87f08384fd9d988a117b4ce6839b466c4c65834a9195d3104d4640c5edb978f11668ea364cfacfa560e78adb81040b1cb105e33e946a0f07a6a3b04feb2dcd9211a6526d7f1177a7e4b2e00e9eb237381577b9ca51ddd7392b1050404170092d53d0126dd6a01a6490aa48f45cb6a8b946441411386309b2d25fc3158ee5029c6c34c845a053a796319aa3028e9862f6ee96aab9b5b7e1c61197d7964047c115932f42fa0395a62e2b3d969bc2e331b1a8e800b36cf622dbd1d5d9058874457647abfe88be2be21899d7f0cb20b3f521edc5cadffe0d4da70c8adf6cc8c720c47951a0d42f19b0e38708532747a57a2a6df2928fb9e8e62e9f2455e2272900ad208e819403de9c93ae10ab06c21307d607e9ca2c9647c29f5b3d5ce9e287e26056ad20e7911890b498cb1d01366fe632ca2405e10cec3330fa0d12287cfccf05a93f2ead201c07930bde76bfee7b919c6f32c2fd2c4613bbc4eb64a06d2e5c0abe7d0184b5ad2097f65ac6f8c7c4bbd153631019edaaa293d1045fbe9bb5f64ac7744dd0c8abddad510063030102031401010101010101010101010101010101010101016841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51e610773dd968e4d63d83379dacabf35c82a7e438bf691b3b03df6f502136b25f";
        depositScript = hex"20c47951a0d42f19b0e38708532747a57a2a6df2928fb9e8e62e9f2455e2272900ad208e819403de9c93ae10ab06c21307d607e9ca2c9647c29f5b3d5ce9e287e26056ad20e7911890b498cb1d01366fe632ca2405e10cec3330fa0d12287cfccf05a93f2ead201c07930bde76bfee7b919c6f32c2fd2c4613bbc4eb64a06d2e5c0abe7d0184b5ad2097f65ac6f8c7c4bbd153631019edaaa293d1045fbe9bb5f64ac7744dd0c8abddad5100630301020314";
        intermediate_nodes = hex"0000000000000000000000000000000000000000000000000000000000000000e1a597d064a290f1f05e6ed9cdff56da7f75381748ca0a3b61c1ddb5d599b40ee5d186d6db369c1da7f39254ae8194add508758582edb82e054eb9f9e686392c8f2dbfe4702b6b29547006c140765a109f5d9027b6583c859a2224c4322c58080d351c7e59dedd8e2ec4b07bb253a59c8589d1755668895652283c19a30285f1";
        witnessRoot = hex"b615b861dae528f99e15f37cb755f9ee8a02be8bd870088e3f329cde8609730b";

        vm.startPrank(SYSTEM_CALLER);
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_2"), witnessRoot);
        
        vm.expectRevert("Invalid deposit script");
        // Incremented 1 block, that's why `doDeposit` is not used
        Bridge.DepositParams memory depositParams = Bridge.DepositParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER + 1, index);
        bridge.deposit(depositParams);
        vm.stopPrank();
    }

    function testCannotDepositWithATxNotInBlock() public {
        // Tries the hard coded txn on another block with a different witness root
        witnessRoot = hex"b615b861dae528f99e15f37cb755f9ee8a02be8bd870088e3f329cde8609730b";
        vm.startPrank(SYSTEM_CALLER);
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_2"), witnessRoot);

        vm.expectRevert("Transaction is not in block");
        Bridge.DepositParams memory depositParams = Bridge.DepositParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER + 1, index);
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
        bridge.withdraw{value: DEPOSIT_AMOUNT - 1}(hex"1234");
        vm.stopPrank();
    }

    function testNonOperatorCannotDeposit() public {
        vm.expectRevert("caller is not the operator");
        Bridge.DepositParams memory depositParams = Bridge.DepositParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER, index);
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
        vm.prank(owner);
        bridge.setDepositScript(depositScript, scriptSuffix, 5);
        assert(bridge.isBytesEqual_(depositScript, bridge.depositScript()));
        assert(bridge.isBytesEqual_(scriptSuffix, bridge.scriptSuffix()));
        assertEq(5, bridge.requiredSigsCount());
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
        Bridge.DepositParams memory depositParams = Bridge.DepositParams(version, flag, vin, vout, witness, locktime, intermediate_nodes, INITIAL_BLOCK_NUMBER, index);
        bridge.deposit(depositParams);
        vm.stopPrank();
    }
}