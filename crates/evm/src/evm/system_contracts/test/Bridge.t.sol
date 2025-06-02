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

    function verifySigInTx_(bytes memory input, bytes memory output, bytes memory witness0, bytes4 version, bytes4 locktime, bytes32 shaScriptPubkeys) public view {
        super.verifySigInTx(input, output, witness0, version, locktime, shaScriptPubkeys);
    }
}

contract RevertingReceiver {}

contract FalseBridge is Bridge {
    function falseFunc() public pure returns (bytes32) {
        return keccak256("false");
    }
}

contract MockSchnorrPrecompile {
    // Modified from https://github.com/zerodao-finance/bip340-solidity
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant NN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141; // curve order
    uint256 constant private U255_MAX_PLUS_1 = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

    fallback(bytes calldata) external returns (bytes memory) {
        uint256 px;
        uint256 rx;
        uint256 s;
        bytes32 m;
        
        assembly {
            px := calldataload(0)
            m := calldataload(32)
            rx := calldataload(64)
            s := calldataload(96)
        }
        
        return abi.encode(verify(px, rx, s, m));
    }

    function verify(uint256 px, uint256 rx, uint256 s, bytes32 m) public pure returns (bytes memory) {
        // Check pubkey, rx, and s are in-range.
        if (px >= PP || rx >= PP || s >= NN) {
            return hex"";
        }
        
        (address exp_, bool ok) = convToFakeAddr(rx);
        if (!ok) {
            return hex"";
        }
        
        uint256 e = computeChallenge(bytes32(rx), bytes32(px), m);
        bytes32 sp = bytes32(NN - mulmod(s, px, NN));
        bytes32 ep = bytes32(NN - mulmod(e, px, NN));
        address rvh = ecrecover(sp, 27, bytes32(px), ep);
        
        assembly {
            if eq(rvh, exp_) {
                let result := mload(0x40)
                mstore(0x40, add(result, 0x20))
                mstore(result, 1)
                return(result, 0x20)
            }
            let result := mload(0x40)
            mstore(0x40, result)
            return(result, 0)
        }
    }

    function liftX(uint256 _x) internal pure returns (uint256, bool) {
        if (_x >= PP) {
            return (0, false);
        }
        
        // Taken from the EllipticCurve code.
        uint256 y2 = addmod(mulmod(_x, mulmod(_x, _x, PP), PP), addmod(mulmod(_x, AA, PP), BB, PP), PP);
        y2 = expMod(y2, (PP + 1) / 4, PP);
        uint256 y = (y2 & 1) == 0 ? y2 : PP - y2;

        return (y, true);
    }

    function convToFakeAddr(uint256 px) internal pure returns (address, bool) {
        (uint256 py, bool ok) = liftX(px);
        if (!ok) {
            return (address(0), false);
        }
        bytes32 h = keccak256(abi.encodePacked(bytes32(px), bytes32(py)));
        return (address(uint160(uint256(h))), true);
    }

    function computeChallenge(bytes32 rx, bytes32 px, bytes32 m) internal pure returns (uint256) {
        // Precomputed `sha256("BIP0340/challenge")`.
        //
        // Saves ~10k gas, mostly from byte shuffling to prepare the call.
        //bytes32 tag = sha256("BIP0340/challenge");
        bytes32 tag = 0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c;

        // Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
        return uint256(sha256(abi.encodePacked(tag, tag, rx, px, m))) % NN;
    }

    function expMod(uint256 _base, uint256 _exp, uint256 _pp) internal pure returns (uint256) {
        require(_pp!=0, "Modulus is zero");

        if (_base == 0)
        return 0;
        if (_exp == 0)
        return 1;

        uint256 r = 1;
        uint256 bit = U255_MAX_PLUS_1;
        assembly {
        for { } gt(bit, 0) { }{
            r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, bit)))), _pp)
            r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 2))))), _pp)
            r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 4))))), _pp)
            r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 8))))), _pp)
            bit := div(bit, 16)
        }
        }

        return r;
  }
}

contract BridgeTest is Test {
    using BytesLib for bytes;
    using BTCUtils for bytes;

    uint256 constant DEPOSIT_AMOUNT = 10 ether;
    BridgeHarness public bridge = BridgeHarness(address(0x3100000000000000000000000000000000000002));
    bytes2 flag = hex"0001";
    bytes4 version = hex"03000000";
    bytes vin = hex"012f3175921222c511f5b382996685b25b694cf00d308de61087b25eb302cc46fd0000000000fdffffff";
    bytes vout = hex"0210c99a3b0000000022512040b87e69e03b5535637a6fcc3ee4fee978e57944261c06b71c88a47d2d61e1b3f0000000000000000451024e73";
    bytes4 locktime = hex"00000000";
    bytes witness = hex"0340c8ab5934617fe53e02543345880afd0fad024bc4045570e31fc25bf3a66d8b34ae4a29ec34963dc428a882f8fe3c9d96ca8bf8f41f2ddd89110f20d76655f2754a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114010101010101010101010101010101010101010108000000003b9aca006841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de5162e2acaa4eb5dcc1d4bfb32d9e12d444861378d4a2ccfd7d8ba97d4970be096b";
    bytes depositPrefix = hex"4a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114";
    bytes depositSuffix = hex"08000000003b9aca0068";
    bytes intermediateNodes = hex"7e3bfb74009ffaa87436e5af4229178bc9ff6a8a2c5e726854912b136dd214215066ac03deadb1a4694d24189d8bb4607d80cb74da5ce59995e7f2c51c0aa9df7661ddbe37aa5059282d818f51446a40d5bcfb5af24683f357d7f0faae0a1a92";
    uint256 index = 5;
    bytes32 shaScriptPubkeys = hex"cc17c6434cbe073dadf43e8b9840a2596ec30af84ff6bbf03afeba4d5d6bd42d";

    address constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);
    address receiver = address(0x0101010101010101010101010101010101010101);
    address user = makeAddr("citrea_user");
    address owner = makeAddr("citrea_owner");
    address operator;
    uint256 constant INITIAL_BLOCK_NUMBER = 1;
    bytes32 witnessRoot = hex"2d12d1dac06d40bbf364be911d9dc2cf07538e2118c88fdba457a5e5fa59c851";
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
        
        // Mock Schnorr verifier precompile
        vm.etch(address(0x200), address(new MockSchnorrPrecompile()).code);

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

        vm.prank(owner);
        operator = makeAddr("citrea_operator");
        bridge.setOperator(operator);
    }

    function testDeposit() public {
        doDeposit();
        // Assert if asset transferred
        assertEq(receiver.balance, DEPOSIT_AMOUNT);
        assertTrue(bridge.processedTxIds(hex"663453afeb5214bc2e60f40d4dc0a8a275324db880fe3233e7d677fb85ebf929"));
        assertEq(bridge.depositTxIds(0), hex"663453afeb5214bc2e60f40d4dc0a8a275324db880fe3233e7d677fb85ebf929");
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
        vm.startPrank(owner);
        bridge.setDepositScript(hex"4a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656115", hex"08000000003b9aca0068");
        vm.stopPrank();
        vm.startPrank(operator);
        Bridge.Transaction memory depositTx = Bridge.Transaction(version, flag, vin, vout, witness, locktime);
        Bridge.MerkleProof memory proof = Bridge.MerkleProof(intermediateNodes, INITIAL_BLOCK_NUMBER, index);
        vm.expectRevert("Invalid deposit script");
        bridge.deposit(depositTx, proof, shaScriptPubkeys);
        vm.stopPrank();
    }

    function testCannotDepositWithATxNotInBlock() public {
        // Tries the hard coded txn on another block with a different witness root
        witnessRoot = hex"b615b861dae528f99e15f37cb755f9ee8a02be8bd870088e3f329cde8609730b";
        vm.startPrank(SYSTEM_CALLER);
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_2"), witnessRoot, 3);

        vm.expectRevert("Transaction is not in block");
        Bridge.Transaction memory depositTx = Bridge.Transaction(version, flag, vin, vout, witness, locktime);
        Bridge.MerkleProof memory proof = Bridge.MerkleProof(intermediateNodes, INITIAL_BLOCK_NUMBER + 1, index);
        bridge.deposit(depositTx, proof, shaScriptPubkeys);
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
        vm.expectRevert("caller is not the system caller or operator");
        Bridge.Transaction memory depositTx = Bridge.Transaction(version, flag, vin, vout, witness, locktime);
        Bridge.MerkleProof memory proof = Bridge.MerkleProof(intermediateNodes, INITIAL_BLOCK_NUMBER, index);
        bridge.deposit(depositTx, proof, shaScriptPubkeys);
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
        vm.startPrank(SYSTEM_CALLER);
        version = hex"03000000";
        vin = hex"01f74f0390589e8c83bf9ba99c1872acf63803173654cae97b1c8ec01042d6af650000000000fdffffff";
        vout = hex"0210c99a3b0000000022512040b87e69e03b5535637a6fcc3ee4fee978e57944261c06b71c88a47d2d61e1b3f0000000000000000451024e73";
        witness = hex"034029afe3877d9562c70b50b7d215736579869fb2f8ae30626869b87bdbdab6105ca7adc90d16a246322eb0c9ef1c63847b91f2db38f74aacc3fa72cb1098cb47664a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114564cb100d2d5deceb792fe913b9185fcfb80871208000000003b9aca006841c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de510f2951fffb548259d5abb9f351be8f94031c9ce88ce838b40d7cec7c606e0c7a";
        intermediateNodes = hex"00000000000000000000000000000000000000000000000000000000000000002a3e143606a444e8414861e27d3409466513df018e345609cb9add0c79dd661c";
        witnessRoot = hex"853c333692ff1da2f74e49ac493b630fb98b4587c76f46175c4c0c8a16ec0fd8";
        index = 1;
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_2"), witnessRoot, 2);
        vm.stopPrank();
        vm.startPrank(owner);
        bridge.setDepositScript(hex"4a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114", hex"08000000003b9aca0068");
        bridge.setReplaceScript(hex"54203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630d6369747265615265706c61636520", hex"68");
        vm.stopPrank();
        vm.startPrank(SYSTEM_CALLER);
        Bridge.Transaction memory depositToBeReplacedTx = Bridge.Transaction(version, flag, vin, vout, witness, locktime);
        Bridge.MerkleProof memory proof = Bridge.MerkleProof(intermediateNodes, INITIAL_BLOCK_NUMBER + 1, index);
        bridge.deposit(depositToBeReplacedTx, proof, hex"916d7adc719dd331d47ef21fe3b29014186fa3b294df42221d7c0edea729881f");
        vin = hex"01f7dc30d46c53a660ba2011fd389891736760cddeff5d68ef57afb815076ce86f0000000000fdffffff";
        vout = hex"0210c99a3b0000000022512040b87e69e03b5535637a6fcc3ee4fee978e57944261c06b71c88a47d2d61e1b3f0000000000000000451024e73";
        witness = hex"0340c538ad077a0b4f91915d28cb926674c0c0f57ffd31cbd232d4f30b1390516dd2bfa5aa8cae925528576e29f0d9f219558ca5754648c25595d710107b2158c56154203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630d6369747265615265706c6163652036db3e96dc72a2be198234a326f3443c9326d2546deca3576a1959725a0391086821c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51";
        intermediateNodes = hex"0000000000000000000000000000000000000000000000000000000000000000030486678812997a69add330bc972e229a69e2125590ab73784f55eb680ef801";
        witnessRoot = hex"3e2161fe3b7688914a624e360dae3f3e33caf9395870610c056785d66ec26906";
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_3"), witnessRoot, 2);
        assertEq(bridge.depositTxIds(0), hex"36db3e96dc72a2be198234a326f3443c9326d2546deca3576a1959725a039108");
        vm.stopPrank();
        vm.prank(operator);
        Bridge.Transaction memory replaceTx = Bridge.Transaction(version, flag, vin, vout, witness, locktime);
        proof = Bridge.MerkleProof(intermediateNodes, INITIAL_BLOCK_NUMBER + 2, index);
        bridge.replaceDeposit(replaceTx, proof, 0, hex"486568b2542cc5ebf896e41e17c42e5571e6f3e68020d90d39fe7a2d7f0a68c3");
        assertEq(bridge.depositTxIds(0), hex"6a1d18b80867c0bc84cb9a20ec88922cf17a7bdd50e5237d67b6fad11d70fe95");
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
        Bridge.Transaction memory depositTx = Bridge.Transaction(version, flag, vin, vout, witness, locktime);
        Bridge.MerkleProof memory proof = Bridge.MerkleProof(intermediateNodes, INITIAL_BLOCK_NUMBER, index);
        bridge.deposit(depositTx, proof, shaScriptPubkeys);
        vm.stopPrank();
    }

    function testVerifySigInTx() public {
        version = hex"03000000";
        locktime = hex"00000000";
        vin = hex"012f3175921222c511f5b382996685b25b694cf00d308de61087b25eb302cc46fd0000000000fdffffff";
        vout = hex"0210c99a3b0000000022512040b87e69e03b5535637a6fcc3ee4fee978e57944261c06b71c88a47d2d61e1b3f0000000000000000451024e73";
        witness = hex"0340c8ab5934617fe53e02543345880afd0fad024bc4045570e31fc25bf3a66d8b34ae4a29ec34963dc428a882f8fe3c9d96ca8bf8f41f2ddd89110f20d76655f2754a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114010101010101010101010101010101010101010108000000003b9aca006841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de5162e2acaa4eb5dcc1d4bfb32d9e12d444861378d4a2ccfd7d8ba97d4970be096b";
        vm.startPrank(owner);
        bridge.setDepositScript(hex"4a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114", hex"08000000003b9aca0068");
        Bridge.Transaction memory testParams = Bridge.Transaction(version, flag, vin, vout, witness, locktime);
        bytes memory input = testParams.vin.extractInputAtIndex(0);
        bytes memory output = testParams.vout.slice(1, testParams.vout.length - 1);
        bytes memory witness0 = WitnessUtils.extractWitnessAtIndex(testParams.witness, 0);
        bridge.verifySigInTx_(input, output, witness0, version, locktime, shaScriptPubkeys);
    }

    function testCannotVerifySigInTx() public {
        version = hex"03000000";
        locktime = hex"00000000";
        vin = hex"012f3175921222c511f5b382996685b25b694cf00d308de61087b25eb302cc46fd0000000000fdffffff";
        vout = hex"0210c99a3b0000000022512040b87e69e03b5535637a6fcc3ee4fee978e57944261c06b71c88a47d2d61e1b3f0000000000000000451024e73";
        witness = hex"0340c8ab5934617fe53e02543345880afd0fad024bc4045570e31fc25bf3a66d8b34ae4a29ec34963dc428a882f8fe3c9d96ca8bf8f41f2ddd89110f20d76655f2754a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114010101010101010101010101010101010101010108000000003b9aca006841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de5162e2acaa4eb5dcc1d4bfb32d9e12d444861378d4a2ccfd7d8ba97d4970be096b";
        vm.startPrank(owner);
        bridge.setDepositScript(hex"4a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114", hex"08000000003b9aca0068");
        Bridge.Transaction memory testParams = Bridge.Transaction(version, flag, vin, vout, witness, locktime);
        bytes memory input = testParams.vin.extractInputAtIndex(0);
        bytes memory output = testParams.vout.slice(1, testParams.vout.length - 1);
        bytes memory witness0 = WitnessUtils.extractWitnessAtIndex(testParams.witness, 0);
        vm.expectRevert("Invalid signature");
        bridge.verifySigInTx_(input, output, witness0, version, locktime, hex"");
    }

    function testDepositRedirectsWhenReceiverReverts() public {
        RevertingReceiver rev = new RevertingReceiver();
        vm.etch(receiver, address(rev).code); 

        address vault = bridge.failedDepositVault(); 
        uint256 vaultBalBefore = vault.balance;

        vm.startPrank(operator);
        Bridge.Transaction memory txn = Bridge.Transaction(version, flag, vin, vout, witness, locktime);
        Bridge.MerkleProof memory proof = Bridge.MerkleProof(intermediateNodes, INITIAL_BLOCK_NUMBER, index);
        vm.expectEmit();
        emit Bridge.DepositTransferFailed(
            hex"45957fe9a9bdb8e6c4a81bedbc55a0093105aa8eb6c3f2d8dc7bab6e9fd04fe9",
            hex"663453afeb5214bc2e60f40d4dc0a8a275324db880fe3233e7d677fb85ebf929",
            receiver,
            block.timestamp,
            0
        );
        bridge.deposit(txn, proof, shaScriptPubkeys);
        vm.stopPrank();

        assertEq(receiver.balance, 0);

        assertEq(vault.balance, vaultBalBefore + DEPOSIT_AMOUNT);

        assertTrue(bridge.processedTxIds(hex"663453afeb5214bc2e60f40d4dc0a8a275324db880fe3233e7d677fb85ebf929"));
    }
    

    function testSecondDepositId() public {
        doDeposit();
        vm.startPrank(SYSTEM_CALLER);
        version = hex"03000000";
        vin = hex"01f74f0390589e8c83bf9ba99c1872acf63803173654cae97b1c8ec01042d6af650000000000fdffffff";
        vout = hex"0210c99a3b0000000022512040b87e69e03b5535637a6fcc3ee4fee978e57944261c06b71c88a47d2d61e1b3f0000000000000000451024e73";
        witness = hex"034029afe3877d9562c70b50b7d215736579869fb2f8ae30626869b87bdbdab6105ca7adc90d16a246322eb0c9ef1c63847b91f2db38f74aacc3fa72cb1098cb47664a203b48ffb437c2ee08ceb8b9bb9e5555c002fb304c112e7e1233fe233f2a3dfc1dac00630663697472656114564cb100d2d5deceb792fe913b9185fcfb80871208000000003b9aca006841c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de510f2951fffb548259d5abb9f351be8f94031c9ce88ce838b40d7cec7c606e0c7a";
        intermediateNodes = hex"00000000000000000000000000000000000000000000000000000000000000002a3e143606a444e8414861e27d3409466513df018e345609cb9add0c79dd661c";
        witnessRoot = hex"853c333692ff1da2f74e49ac493b630fb98b4587c76f46175c4c0c8a16ec0fd8";
        index = 1;
        bitcoinLightClient.setBlockInfo(keccak256("CITREA_TEST_2"), witnessRoot, 2);

        Bridge.Transaction memory secondTx = Bridge.Transaction(version, flag, vin, vout, witness, locktime);
        Bridge.MerkleProof memory proof = Bridge.MerkleProof(intermediateNodes, INITIAL_BLOCK_NUMBER + 1, index);

        vm.expectEmit();
        emit Bridge.Deposit(hex"06b48f9d832a6a4dba7ecfc5335f7047a4a0823a5b2975bdad334c8e50b94985", hex"36db3e96dc72a2be198234a326f3443c9326d2546deca3576a1959725a039108", address(0x564CB100d2D5DecEB792fe913B9185FCFB808712), block.timestamp, 1);

        bridge.deposit(secondTx, proof, hex"916d7adc719dd331d47ef21fe3b29014186fa3b294df42221d7c0edea729881f");

        vm.stopPrank();
    }

    function testSafeWithdraw() public {
        doDeposit();
        vm.prank(SYSTEM_CALLER);
        bitcoinLightClient.setBlockInfo(hex"d740c1b74570c512cb79c8b3f5d3ccaa515059c49dd51b01c5b2ec56bfb9ee37", witnessRoot, 2);
        vm.startPrank(receiver);
        Bridge.Transaction memory prepareTx = Bridge.Transaction(
            hex"02000000", 
            hex"0001", 
            hex"0180f01d40c4c53e10a58e0e63d84ee369173c3b03e9c4787f33416beefac82f910000000000fdffffff", 
            hex"02e7251a1e01000000225120af6d60391056de5e15fd91efc05330439f58eaa811a24fe4bba53cd8c660562c26020000000000002251202a64b1ee3375f3bb4b367b8cb8384a47f73cf231717f827c6c6fbbf5aecf0c36", 
            hex"01404344971b6185f8724449b964393220cf37cbc124727ad29df7540ee9048f47a704845f8f3d7c2c240ae904c45de08b0187cc41745d5266b8e5a5d092d30ed19b",
            hex"d5000000"
        );
        Bridge.MerkleProof memory proof = Bridge.MerkleProof(
            hex"f70aa9fc12ea0cea3947a2892e8b4c2970b1d7f1cb3e2411dc83141d17b1ce5573a03a23cb4e62a4ae2eb692ff0cef81f6289472694613dd83a3e40251ad6dbf",
            INITIAL_BLOCK_NUMBER + 1,
            2
        );
        Bridge.Transaction memory payoutTx = Bridge.Transaction(
            hex"02000000", 
            hex"0001", 
            hex"019e7138d6bebcc9cab3de962a1d2dd35163d49a0f9053ad1afc9cd5539249af780100000000fdffffff", 
            hex"016043993b000000002251209baa4044688dbec6a8b2044155f3d82b80fbc007115154c04eefd64491262f90", 
            hex"0141834e7a701035bb446dd4112c3a0498c1d7b44f89000f2c14e9a3ef8c04a05e6b1faa5727d1a7a62e6d46b7942ee17cb6766bde46f5b5d1e4337c57240e3c712a83",
            hex"00000000"
        );
        bytes memory header = hex"00000030a49f936b31bbd053f48f8b3e55666124607917271e93d1d4c942f2139bbe9a2e402f348e5912a77a6273511b017659b8fcb9484b73241527178e4b924848e9b062802c68ffff7f2001000000";
        bridge.safeWithdraw{value: DEPOSIT_AMOUNT}(prepareTx, proof, payoutTx, header, hex"51209baa4044688dbec6a8b2044155f3d82b80fbc007115154c04eefd64491262f90");
        assertEq(receiver.balance, 0);
        // Assert if withdrawal UTXO is stored properly
        uint256 withdrawalCount = bridge.getWithdrawalCount();
        (bytes32 txId, bytes4 outputId) = bridge.withdrawalUTXOs(withdrawalCount - 1);
        assertEq(txId, hex"9e7138d6bebcc9cab3de962a1d2dd35163d49a0f9053ad1afc9cd5539249af78");
        assertEq(outputId, hex"01000000");  
    }
}