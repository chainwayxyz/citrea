// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import "./Bridge.sol";

contract BridgeMigrationState {
    address public constant BRIDGE = 0x3100000000000000000000000000000000000002;

    uint256 public withdrawalCount;
    uint256 public depositCount;
    uint256 public newDepositAmount;
    uint256 public splitCount;
    uint256 public splitIndex;

    modifier onlyBridge() {
        require(msg.sender == BRIDGE, "caller is not the bridge");
        _;
    }

    function start(uint256 _withdrawalCount, uint256 _depositCount, uint256 _newDepositAmount, uint256 _depositAmount) external onlyBridge {
        require(splitCount == 0, "Migration already started");
        require(_newDepositAmount != 0 && _newDepositAmount < _depositAmount, "Invalid deposit amount");
        require(_depositAmount % _newDepositAmount == 0, "Deposit amount must divide evenly");
        require(_newDepositAmount % Bridge(BRIDGE).SAT_TO_WEI() == 0, "Deposit amount must have valid satoshi value");
        withdrawalCount = _withdrawalCount;
        depositCount = _depositCount;
        newDepositAmount = _newDepositAmount;
        splitCount = _depositAmount / _newDepositAmount;
        splitIndex = _withdrawalCount;
    }

    function setSplitIndex(uint256 _splitIndex) external onlyBridge {
        splitIndex = _splitIndex;
    }

    function validate(uint256 _withdrawalLength, uint256 _depositLength, uint256 _depositAmount) external view {
        require(splitCount != 0, "Migration not started");
        require(splitIndex == depositCount, "Deposits not split");
        require(_withdrawalLength == depositCount, "Unexpected withdrawal count");
        require(_depositLength == depositCount + (depositCount - withdrawalCount) * splitCount, "Unexpected deposit count");
        require(_depositAmount == newDepositAmount, "Deposit amount not set");
    }
}
