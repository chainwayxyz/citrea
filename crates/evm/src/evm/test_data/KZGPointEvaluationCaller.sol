
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract KZGPointEvaluationCaller {
    /// @notice Calls the 0x0A precompile to perform point evaluation
    /// @param input A 192-byte input representing the polynomial versioned hash, commitment, point, and proof
    function verifyPointEvaluation(
        bytes calldata input // 192 bytes
    ) external returns (bool success) {
        require(input.length == 192, "Invalid input size");
        bytes memory out;
        (success, out) = address(10).staticcall(input);
        require(out.length == 0);
        // Write the 32 bytes of out to first storage slot
        assembly {
            sstore(0, mload(add(out, 64)))
        }
        require(success);
    }
}