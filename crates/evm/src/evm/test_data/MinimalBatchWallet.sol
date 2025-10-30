// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// solc --abi --bin MinimalBatchWallet.sol --overwrite -o .

/**
 * @title MinimalBatchWallet
 * @dev ERC-7579-like wallet for batch execution testing
 */
contract MinimalBatchWallet {
    // Execute function that handles both single and batch operations
    function execute(bytes32 mode, bytes calldata executionData) external payable {
        // Decode execution data based on mode
        // Mode determines single vs batch execution
        uint256 modeInt = uint256(mode);
        require(modeInt == 0x01 || modeInt == 0x00, "Invalid mode");

        if (modeInt == 0x01) {
            // Batch mode
            (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
                abi.decode(executionData, (address[], uint256[], bytes[]));

            require(targets.length == values.length, "Target-value length mismatch");
            require(targets.length == datas.length, "Target-data length mismatch");
            require(targets.length > 0, "Empty batch");

            for (uint256 i = 0; i < targets.length; i++) {
                require(targets[i] != address(0), "Target is zero address");
                (bool success, bytes memory returnData) = targets[i].call{value: values[i]}(datas[i]);
                if (!success) {
                    // Bubble up the revert reason
                    if (returnData.length > 0) {
                        assembly {
                            revert(add(returnData, 32), mload(returnData))
                        }
                    } else {
                        revert("Batch call failed");
                    }
                }
            }
        } else {
            // Single execution mode
            (address target, uint256 value, bytes memory data) =
                abi.decode(executionData, (address, uint256, bytes));

            require(target != address(0), "Target is zero address");
            (bool success, bytes memory returnData) = target.call{value: value}(data);
            if (!success) {
                // Bubble up the revert reason
                if (returnData.length > 0) {
                    assembly {
                        revert(add(returnData, 32), mload(returnData))
                    }
                } else {
                    revert("Single call failed");
                }
            }
        }
    }

    // Receive function to accept ETH
    receive() external payable {}
}