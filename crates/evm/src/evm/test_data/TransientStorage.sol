// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

contract TransientStorage {
    mapping(address => bool) sentGifts;
    bool transient locked;

    modifier nonReentrant {
        require(!locked, "Reentrancy attempt");
        locked = true;
        _;
        // Unlocks the guard, making the pattern composable.
        // After the function exits, it can be called again, even in the same transaction.
        locked = false;
    }

    function claimGift() nonReentrant public {
        require(address(this).balance >= 1 ether);
        require(!sentGifts[msg.sender]);
        (bool success, ) = msg.sender.call{value: 1 ether}("");
        require(success);

        // In a reentrant function, doing this last would open up the vulnerability
        sentGifts[msg.sender] = true;
    }

    // Function to receive Ether. This is required to receive Ether into the contract
    receive() external payable {}
}