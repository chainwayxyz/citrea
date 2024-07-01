// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./FeeVault.t.sol";
import "../src/PriorityFeeVault.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";


contract PriorityFeeVaultTest is FeeVaultTest {
    function setUp() public {
        feeVault = PriorityFeeVault(payable(address(0x3100000000000000000000000000000000000005)));
        address priorityFeeVaultImpl = address(new PriorityFeeVault());
        address erc1967Impl = address(new ERC1967Proxy(priorityFeeVaultImpl, ""));
        vm.etch(address(feeVault), erc1967Impl.code);
        bytes32 IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        bytes32 OWNER_SLOT = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;
        bytes32 RECIPIENT_SLOT = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes32 MIN_WITHDRAW_SLOT = 0x0000000000000000000000000000000000000000000000000000000000000001;
        vm.store(address(feeVault), IMPLEMENTATION_SLOT, bytes32(uint256(uint160(priorityFeeVaultImpl))));
        vm.store(address(feeVault), OWNER_SLOT, bytes32(uint256(uint160(owner))));
        vm.store(address(feeVault), RECIPIENT_SLOT, bytes32(uint256(uint160(recipient))));
        vm.store(address(feeVault), MIN_WITHDRAW_SLOT, bytes32(uint256(0.5 ether)));
    }
}