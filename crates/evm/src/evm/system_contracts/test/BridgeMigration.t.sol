// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "../src/BridgeMigration.sol";
import {MockSchnorrPrecompileAlwaysAccept} from "./Bridge.t.sol";

contract BridgeMigrationForkTest is Test {
    BridgeMigration bridge = BridgeMigration(payable(0x3100000000000000000000000000000000000002));
    BitcoinLightClient lightClient = BitcoinLightClient(0x3100000000000000000000000000000000000001);
    ProxyAdmin proxyAdmin = ProxyAdmin(0x31fFFfFfFFFffFFFFFFfFFffffFFffffFfFFfffF);
    address owner = 0x7EE7fb894B5b554A8eb44d570DF4B67Adc964d0b;
    address operator = 0x638689E8367Ad0f32102486866A6788a80AE360F;
    address recipient = address(0xbeef);
    bytes32 signer = 0x67951411385138004e082a07c45f30dc387a78220d639f33c829c5a12a436055;

    function testMigrateMainnetToTwoBtc() public {
        vm.createSelectFork("https://rpc.mainnet.citrea.xyz");
        vm.etch(address(0x200), address(new MockSchnorrPrecompileAlwaysAccept()).code);
        uint256 withdrawalCount = bridge.getWithdrawalCount();
        uint256 splitCount = bridge.depositAmount() / 2 ether;

        vm.startPrank(owner);
        bridge.pause();
        proxyAdmin.upgrade(ITransparentUpgradeableProxy(address(bridge)), address(new BridgeMigration()));
        bridge.startMigration(2 ether);
        uint256 depositCount = bridge.migration().depositCount();
        uint256 liveCount = depositCount - withdrawalCount;
        bridge.padWithdrawalUTXOs(liveCount);
        bridge.splitDeposits(liveCount);
        bridge.setDepositAmount();
        bridge.validateMigration();

        uint256 totalCount = depositCount + liveCount * splitCount;
        assertEq(bridge.getWithdrawalCount(), depositCount);
        assertEq(bridge.depositTxIds(totalCount - 1), fakeTxId(bridge.depositTxIds(depositCount - 1), uint32(splitCount - 1)));
        vm.expectRevert();
        bridge.depositTxIds(totalCount);

        proxyAdmin.upgrade(ITransparentUpgradeableProxy(address(bridge)), address(new Bridge()));
        bytes32[] memory signers = new bytes32[](1);
        signers[0] = signer;
        bridge.setSigners(signers);
        bridge.unpause();
        vm.stopPrank();

        bytes32 fake = fakeTxId(bridge.depositTxIds(withdrawalCount), 0);
        Bridge.Transaction memory replaceTx = signedTx(bytes32(uint256(1)), abi.encodePacked(bridge.replacePrefix(), fake, bridge.replaceSuffix()));
        Bridge.MerkleProof memory proof = includeInNewBlock(replaceTx);
        vm.prank(operator);
        bridge.replaceDeposit(replaceTx, proof, depositCount, bytes32(0));
        assertEq(bridge.depositTxIds(depositCount), txId(replaceTx));

        Bridge.Transaction memory moveTx = signedTx(bytes32(uint256(2)), abi.encodePacked(bridge.depositPrefix(), recipient, bridge.depositSuffix()));
        proof = includeInNewBlock(moveTx);
        uint256 balanceBefore = recipient.balance;
        vm.prank(operator);
        bridge.deposit(moveTx, proof, bytes32(0));
        assertEq(recipient.balance, balanceBefore + 2 ether);
        assertEq(bridge.depositTxIds(totalCount), txId(moveTx));
    }

    function fakeTxId(bytes32 sourceTxId, uint32 splitIndex) internal pure returns (bytes32) {
        return sha256(abi.encodePacked("CITREA_DEPOSIT_SPLIT", sourceTxId, splitIndex));
    }

    function signedTx(bytes32 prevTxId, bytes memory script) internal view returns (Bridge.Transaction memory) {
        return Bridge.Transaction({
            version: hex"02000000",
            flag: hex"0001",
            vin: abi.encodePacked(hex"01", prevTxId, hex"0000000000fdffffff"),
            vout: abi.encodePacked(hex"0100c2eb0b00000000225120", signer),
            witness: abi.encodePacked(hex"0340", new bytes(64), script, hex"21c0", signer),
            locktime: hex"00000000"
        });
    }

    function includeInNewBlock(Bridge.Transaction memory t) internal returns (Bridge.MerkleProof memory) {
        uint256 height = lightClient.blockNumber();
        bytes32 wtxId = BTCUtils.hash256View(abi.encodePacked(t.version, t.flag, t.vin, t.vout, t.witness, t.locktime));
        vm.prank(bridge.SYSTEM_CALLER());
        lightClient.setBlockInfo(keccak256(abi.encode(height)), wtxId, 0);
        return Bridge.MerkleProof("", height, 0);
    }

    function txId(Bridge.Transaction memory t) internal view returns (bytes32) {
        return ValidateSPV.calculateTxId(t.version, t.vin, t.vout, t.locktime);
    }
}
