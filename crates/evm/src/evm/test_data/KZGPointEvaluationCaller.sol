// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract KZGPointEvaluationCaller {
    /// @notice Calls the 0x0A precompile to perform point evaluation
    /// @param input A 192-byte input representing the polynomial versioned hash, commitment, point, and proof
    function verifyPointEvaluation(
        bytes calldata input // 192 bytes
    ) external returns (bool success) {
        require(input.length == 192, "Invalid input size");

        assembly {
            // Copy the 192-byte input data from calldata to memory at position 0
            calldatacopy(0, input.offset, 192)

            // Call the precompile at address 0x0A (0x0A is the precompile address)
            let result := staticcall(gas(), 0x0A, 0, 192, 0, 0)

            // Set the success flag based on the precompile result
            success := result

            // Store the result (success) in the contract's storage at slot 0
            sstore(0, success)
        }
    }
}