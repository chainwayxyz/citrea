
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract P256VerifyCaller {
    /// @notice Calls the 0x100 precompile to perform signature verification
    /// @param input A 160-byte input
    function p256Verify(
        bytes calldata input // 160 bytes
    ) external returns (bool success) {
        require(input.length == 160, "Invalid input size");
        bytes memory out;
        (success, out) = address(256).staticcall(input);
        require(success);
        require(out.length == 32);
        // Write the 32 bytes of out to first storage slot
        assembly {
            sstore(0, mload(add(out, 32)))
        }
    }
}
