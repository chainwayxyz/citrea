// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

abstract contract Ownable {
    address public owner;
    address public pendingOwner;

    event OwnershipTransferred(address previousOwner, address newOwner);
    event OwnershipTransferRequested(address previousOwner, address newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not owner");
        _;
    }

    modifier onlyPendingOwner() {
        require(msg.sender == pendingOwner, "Caller is not pending owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function renounceOwnership() public onlyOwner {
        owner = address(0);
        emit OwnershipTransferred(owner, address(0));
    }

    function transferOwnership(address newOwner) public onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferRequested(owner, newOwner);
    }
    
    function acceptOwnership() public onlyPendingOwner {
        address old_owner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(old_owner, pendingOwner);
    }
}