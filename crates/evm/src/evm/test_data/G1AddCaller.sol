
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract G1AddCaller {

    bytes public g1AddResult;

    /// @notice Calls the 0x0b precompile to perform signature verification
    /// @param input A 256-byte input
    function g1Add(
        bytes calldata input // 256 bytes
    ) external returns (bool success) {
        require(input.length == 256, "Invalid input size");
        bytes memory out;
        (success, out) = address(0x0b).staticcall(input);
        require(success);
        require(out.length == 128);
       
        g1AddResult = out;
    }
}
