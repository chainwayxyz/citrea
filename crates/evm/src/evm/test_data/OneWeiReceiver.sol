// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

contract OneWeiReceiver {
    receive() external payable {
        require(msg.value == 1, "Amount must be exactly 1 wei");
    }
}