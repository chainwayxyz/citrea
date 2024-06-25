// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./FeeVault.t.sol";
import "../src/PriorityFeeVault.sol";

contract PriorityFeeVaultTest is FeeVaultTest {
    function setUp() public {
        feeVault = new PriorityFeeVault();
    }
}