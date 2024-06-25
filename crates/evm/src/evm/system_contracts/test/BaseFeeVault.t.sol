// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./FeeVault.t.sol";
import "../src/BaseFeeVault.sol";

contract BaseFeeVaultTest is FeeVaultTest {
    function setUp() public {
        feeVault = new BaseFeeVault();
    }
}