// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./FeeVault.t.sol";
import "../src/L1FeeVault.sol";

contract L1FeeVaultTest is FeeVaultTest {
    function setUp() public {
        feeVault = new L1FeeVault();
    }
}