// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import "./Bridge.sol";
import "./BridgeMigrationState.sol";

contract BridgeMigration is Bridge {
    BridgeMigrationState public immutable migration = new BridgeMigrationState();

    function startMigration(uint256 newDepositAmount) external onlyOwner whenPaused {
        migration.start(withdrawalUTXOs.length, depositTxIds.length, newDepositAmount, depositAmount);
    }

    function padWithdrawalUTXOs(uint256 count) external onlyOwner whenPaused {
        require(count != 0 && withdrawalUTXOs.length + count <= migration.depositCount(), "Invalid count");
        for (uint256 i = 0; i < count; i++) {
            withdrawalUTXOs.push(UTXO({txId: bytes32(type(uint256).max), outputId: bytes4(type(uint32).max)}));
        }
    }

    function splitDeposits(uint256 count) external onlyOwner whenPaused {
        uint256 splitCount = migration.splitCount();
        require(splitCount != 0, "Migration not started");
        require(withdrawalUTXOs.length == migration.depositCount(), "Withdrawals not padded");
        uint256 startIndex = migration.splitIndex();
        uint256 endIndex = startIndex + count;
        require(count != 0 && endIndex <= migration.depositCount(), "Invalid count");
        for (uint256 i = startIndex; i < endIndex; i++) {
            require(withdrawalUTXOs[i].txId == bytes32(type(uint256).max), "Deposit already withdrawn");
            bytes32 sourceTxId = depositTxIds[i];
            for (uint256 j = 0; j < splitCount; j++) {
                bytes32 fakeTxId = sha256(abi.encodePacked("CITREA_DEPOSIT_SPLIT", sourceTxId, uint32(j)));
                depositTxIds.push(fakeTxId);
                depositTxIdToIndex[fakeTxId] = depositTxIds.length;
            }
        }
        migration.setSplitIndex(endIndex);
    }

    function setDepositAmount() external onlyOwner whenPaused {
        require(migration.splitCount() != 0, "Migration not started");
        require(migration.splitIndex() == migration.depositCount(), "Deposits not split");
        uint256 newDepositAmount = migration.newDepositAmount();
        require(newDepositAmount * migration.splitCount() == depositAmount, "Deposit amount mismatch");
        depositAmount = newDepositAmount;
        uint256 _optimisticWithdrawAmountSats = (newDepositAmount / SAT_TO_WEI) - PAYOUT_ANCHOR_OUTPUT_AMOUNT;
        optimisticWithdrawAmountSats = _optimisticWithdrawAmountSats;
        emit OptimisticWithdrawAmountSet(_optimisticWithdrawAmountSats);
    }

    function validateMigration() external view {
        migration.validate(withdrawalUTXOs.length, depositTxIds.length, depositAmount);
    }
}
