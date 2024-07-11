// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "../src/FeeVault.sol";
abstract contract FeeVaultTest is Test {
    FeeVault feeVault;
    ProxyAdmin proxyAdmin = ProxyAdmin(0x31fFFfFfFFFffFFFFFFfFFffffFFffffFfFFfffF);
    address owner = makeAddr("citrea_owner");
    address recipient = makeAddr("citrea_recipient");

    function setUp() public virtual {
        proxyAdmin = new ProxyAdmin();
        vm.etch(address(proxyAdmin), address(proxyAdmin).code);
        vm.store(address(proxyAdmin), bytes32(0), bytes32(uint256(uint160(owner))));
    }

    function testWithdraw() public {
        vm.deal(address(feeVault), 1 ether);
        vm.prank(owner);
        feeVault.withdraw();
        assertEq(address(recipient).balance, 1 ether);
    }

    function testCannotWithdrawLessThanMinWithdraw() public {
        vm.deal(address(feeVault), 0.1 ether);
        vm.startPrank(owner);
        vm.expectRevert("Withdrawal amount must be greater than minimum withdraw amount");
        feeVault.withdraw();
    }

    function testSetRecipient() public {
        vm.prank(owner);
        feeVault.setRecipient(address(this));
        assertEq(feeVault.recipient(), address(this));
    }

    function testSetMinWithdraw() public {
        vm.prank(owner);
        feeVault.setMinWithdraw(1.7 ether);
        assertEq(feeVault.minWithdraw(), 1.7 ether);
    }

    function testCanChangeOwnerAndSetState() public {
        vm.startPrank(owner);
        feeVault.setRecipient(address(this));
        feeVault.setMinWithdraw(1.7 ether);
        assertEq(feeVault.recipient(), address(this));
        assertEq(feeVault.minWithdraw(), 1.7 ether);

        address newOwner = vm.addr(0x1234);
        feeVault.transferOwnership(newOwner);
        vm.stopPrank();
        vm.startPrank(newOwner);
        feeVault.acceptOwnership();
        feeVault.setRecipient(address(1));
        feeVault.setMinWithdraw(0.3 ether);
        assertEq(feeVault.recipient(), address(1));
        assertEq(feeVault.minWithdraw(), 0.3 ether);
    }

    function testNonOwnerCannotChangeState() public {
        address nonOwner = vm.addr(0x1234);
        vm.startPrank(nonOwner);
        vm.expectRevert();
        feeVault.setRecipient(address(1));
        vm.expectRevert();
        feeVault.setMinWithdraw(0.3 ether);
    }
}