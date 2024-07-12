// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";

/// @title Fee accumulator contract template
/// @author Citrea

abstract contract FeeVault is Ownable2StepUpgradeable {
    address public recipient;
    uint256 public minWithdraw;

    uint256[50] private __gap;

    event RecipientUpdated(address oldRecipient, address newRecipient);
    event MinWithdrawUpdated(uint256 oldMinWithdraw, uint256 newMinWithdraw);
    
    receive() external payable {}

    /// @notice Withdraws accumulated fees to recipient if enough funds are accumulated
    function withdraw() external {
        require(address(this).balance >= minWithdraw, "Withdrawal amount must be greater than minimum withdraw amount");
        (bool success, ) = payable(recipient).call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }

    /// @notice Sets the new recipient address for the withdrawn fees
    /// @param _recipient New recipient address
    function setRecipient(address _recipient) external onlyOwner {
        address oldRecipient = recipient;
        recipient = _recipient;
        emit RecipientUpdated(oldRecipient, _recipient);
    }

    /// @notice Sets the new minimum withdraw amount
    /// @param _minWithdraw New minimum withdraw amount
    function setMinWithdraw(uint256 _minWithdraw) external onlyOwner {
        uint256 oldMinWithdraw = minWithdraw;
        minWithdraw = _minWithdraw;
        emit MinWithdrawUpdated(oldMinWithdraw, _minWithdraw);
    }
}