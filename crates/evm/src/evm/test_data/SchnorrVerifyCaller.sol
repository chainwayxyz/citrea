// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract SchnorrVerifyCaller {
    /// @notice Calls the 0x200 precompile to perform signature verification
    /// @param input A 128-byte input
    function schnorrVerify(
        bytes calldata input // 128 bytes
    ) external returns (bool success) {
        require(input.length == 128, "Invalid input size");
        bytes memory out;
        (success, out) = address(512).staticcall(input);
        require(success);
        require(out.length == 32);
        // Write the 32 bytes of out to first storage slot
        assembly {
            sstore(0, mload(add(out, 32)))
        }
    }
}