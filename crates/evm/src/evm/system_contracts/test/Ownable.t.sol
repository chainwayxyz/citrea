// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../lib/Ownable.sol";
import "forge-std/Test.sol";

contract OwnableHarness is Ownable {
    constructor () Ownable() { }

    function privilegedFunction() public onlyOwner {
    }
}

contract OwnableTest is Test {
    OwnableHarness ownable;

    function setUp() public {
        ownable = new OwnableHarness();
    }

    function testOnlyOwner() public {
        ownable.privilegedFunction();
        address non_owner = address(0x1);
        vm.startPrank(non_owner);
        vm.expectRevert("Caller is not owner");
        ownable.privilegedFunction();
    }

    function testTransferOwnership() public {
        ownable.transferOwnership(address(0x1));
        assertEq(ownable.pendingOwner(), address(0x1));
    }

    function testAcceptOwnership() public {
        address new_owner = address(0x1);
        ownable.transferOwnership(new_owner);
        vm.startPrank(new_owner);
        ownable.acceptOwnership();
        assertEq(ownable.owner(), new_owner);
    }

    function testRenounceOwnership() public {
        ownable.renounceOwnership();
        assertEq(ownable.owner(), address(0));
    }
}