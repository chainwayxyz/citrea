// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Script } from "forge-std/Script.sol";
import { console2 as console } from "forge-std/console2.sol";
import "openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Upgrade.sol";

import "openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";
import {VmSafe} from "forge-std/Vm.sol";

// Taken from Optimism
// https://github.com/ethereum-optimism/optimism/blob/develop/packages/contracts-bedrock/scripts/libraries/Process.sol
library Process {
    error FfiFailed(string);
    VmSafe private constant vm = VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));
    /// @notice Foundry cheatcode VM.
    function run(string[] memory _command, bool _allowEmpty) public returns (bytes memory stdout_) {
        VmSafe.FfiResult memory result = vm.tryFfi(_command);
        string memory command;
        for (uint256 i = 0; i < _command.length; i++) {
            command = string.concat(command, _command[i], " ");
        }
        if (result.exitCode != 0) {
            revert FfiFailed(string.concat("Command: ", command, "\nError: ", string(result.stderr)));
        }
        // If the output is empty, result.stdout is "[]".
        if (!_allowEmpty && keccak256(result.stdout) == keccak256(bytes("[]"))) {
            revert FfiFailed(string.concat("No output from Command: ", command));
        }
        stdout_ = result.stdout;
    }
}

// Inspired from Optimism's L2Genesis.s.sol
// https://github.com/ethereum-optimism/optimism/blob/develop/packages/contracts-bedrock/scripts/L2Genesis.s.sol
contract GenesisGenerator is Script {
    address internal proxyAdmin = address(0x31fFFfFfFFFffFFFFFFfFFffffFFffffFfFFfffF);
    bytes32 IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 OWNER_SLOT = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300; // from OwnableUpgradeable
    bytes32 FEE_RECIPIENT_SLOT = 0x0000000000000000000000000000000000000000000000000000000000000000;
    bytes32 MIN_WITHDRAW_SLOT = 0x0000000000000000000000000000000000000000000000000000000000000001;
    bytes32 WCBTC_NAME_SLOT = 0x0000000000000000000000000000000000000000000000000000000000000000;
    bytes32 WCBTC_SYMBOL_SLOT = 0x0000000000000000000000000000000000000000000000000000000000000001;
    bytes32 WCBTC_DECIMALS_SLOT = 0x0000000000000000000000000000000000000000000000000000000000000002;
    bytes32 WCBTC_NAME_VALUE = 0x577261707065642043697472656120426974636f696e0000000000000000002c; // "Wrapped Citrea Bitcoin"
    bytes32 WCBTC_SYMBOL_VALUE = 0x574342544300000000000000000000000000000000000000000000000000000a; // "WCBTC"
    bytes32 WCBTC_DECIMALS_VALUE = 0x0000000000000000000000000000000000000000000000000000000000000012; // 18
    uint160 PROXY_IMPL_OFFSET = uint160(0x0100000000000000000000000000000000000000); // uint160(address(proxy)) - uint160(address(impl))

    // Owner of proxy admin, can update contracts
    address internal upgradeOwner;
    // Owner of bridge
    address internal bridgeOwner;
    // Owner of fee vaults
    address internal feeVaultOwner;

    address internal feeRecipient;

    address[] internal devAddresses = 
    [
        address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266),
        address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8),
        address(0x66f68692c03eB9C0656D676f2F4bD13eba40D1B7),
        address(0xaafB7442f7F00B64057C2e9EaE2815bb63Ee0EcE),
        address(0x9fCDf8f60d3009656E50Bf805Cd53C7335b284Fb),
        address(0xe756fdf89367EF428b48BCa2d272Ec8EcEC053fD),
        address(0x3AEEb871F83C85E68fFD1868bef3425eD6649D39),
        address(0xd44821f906E3909b8AE944F7060551c33b922cc9),
        address(0x0f820f428AE436C1000b27577bF5bbf09BfeC8f2),
        address(0xC2F8Eed77da1583f7bae0a3125Dc7BC426002dDE)
    ];


    function run() public {
        upgradeOwner = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
        bridgeOwner = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
        feeVaultOwner = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
        feeRecipient = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
        dealBalanceToDevAddrs();
        dealBalanceToBridge();
        setProxyAdmin();
        setContracts();
        vm.dumpState("./state/genesis.json");
        generateEvmJson("./state/genesis.json", "./state/evm.json", false);
    }

    function runProd() public {
        upgradeOwner = vm.envAddress("UPGRADE_OWNER");
        bridgeOwner = vm.envAddress("BRIDGE_OWNER");
        feeVaultOwner = vm.envAddress("FEE_VAULT_OWNER");
        feeRecipient = vm.envAddress("FEE_RECIPIENT");
        string memory defaultPath = "./state/evmProd.json";
        string memory copyPath = vm.envOr("PROD_JSON_PATH", defaultPath);
        dealBalanceToBridge();
        setProxyAdmin();
        setContracts();
        vm.dumpState("./state/genesisProd.json");
        generateEvmJson("./state/genesisProd.json", copyPath, true);
    }

    function dealBalanceToDevAddrs() internal {
        for (uint i = 0; i < devAddresses.length; i++) {
            vm.deal(devAddresses[i], type(uint120).max);
        }
    }

    function  dealBalanceToBridge() internal {
        address bridge = address(0x3100000000000000000000000000000000000002);
        uint256 balance = 21_000_000 ether;
        vm.deal(bridge, balance);
    }

    function setProxyAdmin() internal {
        vm.etch(proxyAdmin, vm.getDeployedCode("ProxyAdmin"));
        vm.store(proxyAdmin, bytes32(0), bytes32(uint256(uint160(upgradeOwner))));
    }

    function setContracts() internal {
        deployContract("BitcoinLightClient.sol:BitcoinLightClient", 1);
        deployContract("Bridge", 2);
        deployContract("BaseFeeVault", 3);
        deployContract("L1FeeVault", 4);
        deployContract("PriorityFeeVault", 5);
        deployWCBTC();
        deployContract("FailedDepositVault", 7);
    }

    function deployContract(string memory contractName, uint160 index) internal {
        address namespacedProxy = address(uint160(0x3100000000000000000000000000000000000000) + index);
        address namespacedImpl = address(uint160(namespacedProxy) + PROXY_IMPL_OFFSET);
        vm.etch(namespacedImpl, vm.getDeployedCode(contractName));
        address initProxyImpl = address(new TransparentUpgradeableProxy(namespacedImpl, proxyAdmin, ""));
        vm.etch(namespacedProxy, initProxyImpl.code);
        vm.store(namespacedProxy, IMPLEMENTATION_SLOT, bytes32(uint256(uint160(namespacedImpl))));
        vm.store(namespacedProxy, ADMIN_SLOT, bytes32(uint256(uint160(proxyAdmin))));

        // Set owner for bridge contract
        if (index == 2) {
            vm.store(namespacedProxy, OWNER_SLOT, bytes32(uint256(uint160(bridgeOwner))));
        }

        // Fee vault contracts have a fee recipient and min withdraw amount
        if ((index >= 3) && (index <= 7)) {
            vm.store(namespacedProxy, OWNER_SLOT, bytes32(uint256(uint160(feeVaultOwner))));
            vm.store(namespacedProxy, FEE_RECIPIENT_SLOT, bytes32(uint256(uint160(feeRecipient))));
            vm.store(namespacedProxy, MIN_WITHDRAW_SLOT, bytes32(uint256(0.5 ether)));
        } 

        // Remove initial proxy impl code from genesis
        vm.etch(initProxyImpl, "");
        vm.resetNonce(initProxyImpl);
    }

    function deployWCBTC() internal{
        address wcbtc = address(0x3100000000000000000000000000000000000006);
        vm.etch(wcbtc, vm.getDeployedCode("WCBTC9"));
        vm.store(wcbtc, WCBTC_NAME_SLOT, WCBTC_NAME_VALUE);
        vm.store(wcbtc, WCBTC_SYMBOL_SLOT, WCBTC_SYMBOL_VALUE);
        vm.store(wcbtc, WCBTC_DECIMALS_SLOT, WCBTC_DECIMALS_VALUE);
    }

    function generateEvmJson(string memory _genesisPath, string memory _evmPath, bool _isProd) internal {
        string[] memory commands = new string[](3);
        commands[0] = "bash";
        commands[1] = "-c";
        commands[2] = string.concat("python3 ./script/GenesisToEvmJson.py ",  _genesisPath, " ", _evmPath, " ", _isProd ? "true" : "false");
        Process.run(commands, false);
    }
}
