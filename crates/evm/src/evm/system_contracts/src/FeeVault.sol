// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../lib/Ownable.sol";

/// @title Fee accumulator contract template
/// @author Citrea

abstract contract FeeVault is Ownable {
    address public recipient;
    uint256 public minWithdraw = 0.5 ether;

    event RecipientUpdated(address oldRecipient, address newRecipient);
    event MinWithdrawUpdated(uint256 oldMinWithdraw, uint256 newMinWithdraw);
    
    receive() external payable {}

    function withdraw() external {
        require(address(this).balance >= minWithdraw, "Withdrawal amount must be greater than minimum withdraw amount");
        (bool success, ) = payable(recipient).call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }

    function setRecipient(address _recipient) external onlyOwner {
        address oldRecipient = recipient;
        recipient = _recipient;
        emit RecipientUpdated(oldRecipient, _recipient);
    }

    function setMinWithdraw(uint256 _minWithdraw) external onlyOwner {
        uint256 oldMinWithdraw = minWithdraw;
        minWithdraw = _minWithdraw;
        emit MinWithdrawUpdated(oldMinWithdraw, _minWithdraw);
    }
}