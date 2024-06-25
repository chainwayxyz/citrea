// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/FeeVault.sol";
abstract contract FeeVaultTest is Test {
    FeeVault feeVault;

    function testWithdraw() public {
        vm.deal(address(feeVault), 1 ether);
        address recipient = vm.addr(0x1234);
        feeVault.setRecipient(recipient);
        feeVault.withdraw();
        assertEq(address(recipient).balance, 1 ether);
    }

    function testCannotWithdrawLessThanMinWithdraw() public {
        vm.deal(address(feeVault), 0.1 ether);
        address recipient = vm.addr(0x1234);
        feeVault.setRecipient(recipient);
        vm.expectRevert("Withdrawal amount must be greater than minimum withdraw amount");
        feeVault.withdraw();
    }

    function testSetRecipient() public {
        feeVault.setRecipient(address(this));
        assertEq(feeVault.recipient(), address(this));
    }

    function testSetMinWithdraw() public {
        feeVault.setMinWithdraw(1.7 ether);
        assertEq(feeVault.minWithdraw(), 1.7 ether);
    }

    function testCanChangeOwnerAndSetState() public {
        feeVault.setRecipient(address(this));
        feeVault.setMinWithdraw(1.7 ether);
        assertEq(feeVault.recipient(), address(this));
        assertEq(feeVault.minWithdraw(), 1.7 ether);

        address newOwner = vm.addr(0x1234);
        feeVault.transferOwnership(newOwner);
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
        vm.expectRevert("Caller is not owner");
        feeVault.setRecipient(address(1));
        vm.expectRevert("Caller is not owner");
        feeVault.setMinWithdraw(0.3 ether);
    }
}