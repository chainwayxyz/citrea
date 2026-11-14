// SPDX-License-Identifier: MIT
// Note: TouchEmptyAccounts.bin is handcrafted runtime bytecode used for tests.
// This Solidity source is documentation-only and is not compiled in CI.
pragma solidity ^0.8.0;

contract TouchEmptyAccounts {
    function touch(address[10] calldata addrs) external {
        for (uint256 i = 0; i < 10; i++) {
            (bool ok,) = addrs[i].call{value: 0}("");
            ok;
        }
    }
}
