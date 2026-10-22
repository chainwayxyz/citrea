// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

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

    function start(uint256 _withdrawalCount, uint256 _depositCount, uint256 _newDepositAmount, uint256 _splitCount) external onlyBridge {
        require(splitCount == 0, "Migration already started");
        withdrawalCount = _withdrawalCount;
        depositCount = _depositCount;
        newDepositAmount = _newDepositAmount;
        splitCount = _splitCount;
        splitIndex = _withdrawalCount;
    }

    function setSplitIndex(uint256 _splitIndex) external onlyBridge {
        splitIndex = _splitIndex;
    }
}
