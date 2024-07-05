// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Script } from "forge-std/Script.sol";
import { console2 as console } from "forge-std/console2.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract GenesisGenerator is Script {
    address[] internal proxies = [
        0x3100000000000000000000000000000000000001, // BitcoinLightClient
        0x3100000000000000000000000000000000000002, // Bridge
        0x3100000000000000000000000000000000000003, // BaseFeeVault
        0x3100000000000000000000000000000000000004, // L1FeeVault
        0x3100000000000000000000000000000000000005  // PriorityFeeVault
    ];

    function setProxiedContracts() internal {
        address proxyImpl = address(new ERC1967Proxy(address(this), ""));
        for (uint256 i = 0; i < proxies.length; i++) {
            vm.etch(proxies[i], proxyImpl.code);
        }
        

    }
}
