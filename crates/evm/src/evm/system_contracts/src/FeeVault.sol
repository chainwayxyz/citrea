// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import "openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";

/// @title Fee accumulator contract template
/// @author Citrea

/// @dev This contract is not intended for regular deployment and can only be used as a predeploy.
/// @dev It does not utilize OpenZeppelin's initialization chain thus any modifications that include new OZ logic should be made carefully.

abstract contract FeeVault is Ownable2StepUpgradeable {
    address public recipient;
    uint256 public minWithdraw;

    uint256[50] private __gap;

    event Withdrawal(address recipient, uint256 amount);
    event RecipientUpdated(address oldRecipient, address newRecipient);
    event MinWithdrawUpdated(uint256 oldMinWithdraw, uint256 newMinWithdraw);
    
    receive() external payable {}

    /// @notice Withdraws accumulated fees to recipient if enough funds are accumulated
    function withdraw() external {
        address _recipient = recipient;
        require(_recipient != address(0), "Recipient is not set");
        uint256 amount = address(this).balance;
        require(amount >= minWithdraw, "Withdrawal amount must be greater than minimum withdraw amount");
        (bool success, ) = payable(_recipient).call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdrawal(_recipient, amount);
    }

    /// @notice Sets the new recipient address for the withdrawn fees
    /// @param _recipient New recipient address
    function setRecipient(address _recipient) external onlyOwner {
        require(_recipient != address(0), "Recipient cannot be zero address");
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