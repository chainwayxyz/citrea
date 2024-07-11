// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./FeeVault.t.sol";
import "../src/L1FeeVault.sol";

contract L1FeeVaultTest is FeeVaultTest {
    function setUp() public override {
        super.setUp();
        feeVault = L1FeeVault(payable(address(0x3100000000000000000000000000000000000004)));
        address l1FeeVaultImpl = address(new L1FeeVault());
        address proxy_impl = address(new TransparentUpgradeableProxy(l1FeeVaultImpl, address(proxyAdmin), ""));
        vm.etch(address(feeVault), proxy_impl.code);
        bytes32 IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        bytes32 OWNER_SLOT = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;
        bytes32 ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
        bytes32 RECIPIENT_SLOT = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes32 MIN_WITHDRAW_SLOT = 0x0000000000000000000000000000000000000000000000000000000000000001;
        vm.store(address(feeVault), IMPLEMENTATION_SLOT, bytes32(uint256(uint160(l1FeeVaultImpl))));
        vm.store(address(feeVault), OWNER_SLOT, bytes32(uint256(uint160(owner))));
        vm.store(address(feeVault), ADMIN_SLOT, bytes32(uint256(uint160(address(proxyAdmin)))));
        vm.store(address(feeVault), RECIPIENT_SLOT, bytes32(uint256(uint160(recipient))));
        vm.store(address(feeVault), MIN_WITHDRAW_SLOT, bytes32(uint256(0.5 ether)));
    }
}