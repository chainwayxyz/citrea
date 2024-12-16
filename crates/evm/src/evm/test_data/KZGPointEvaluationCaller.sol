
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract KZGPointEvaluation {
    /// @notice Calls the 0x0A precompile to perform point evaluation
    /// @param input A 192-byte input representing the polynomial versioned hash, commitment, point, and proof
    function verifyPointEvaluation(
        bytes calldata input // 192 bytes
    ) external returns (bool success) {
        require(input.length == 192, "Invalid input size");
        bytes memory out;
        (success, out) = address(10).staticcall(input);
        // Write the 32 bytes of out to first storage slot
        assembly {
            sstore(0, mload(add(out, 64)))
        }
        require(success);
        // Read the first storage slot and assert it to be 52435875175126190479447740508185965837690552500527637822603658699938581184513
        assembly {
            if iszero(eq(sload(0), 52435875175126190479447740508185965837690552500527637822603658699938581184513)) {
                revert(0, 0)
            }
        }
    }
}