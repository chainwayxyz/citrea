// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PayableContract {
    address public owner;
    mapping(address => uint) public balances;

    // Constructor sets the contract owner.
    constructor() {
        owner = msg.sender;
    }

    // Function to receive Ether. msg.value contains the Ether amount sent.
    // The payable keyword allows this function to receive Ether.
    receive() external payable {
        balances[msg.sender] += msg.value;
    }

    // Function to withdraw all Ether from this contract to the owner address.
    function withdraw() public {
        require(msg.sender == owner, "Only the owner can withdraw.");
        payable(owner).transfer(address(this).balance);
    }

    // Function to check the contract's Ether balance.
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}
