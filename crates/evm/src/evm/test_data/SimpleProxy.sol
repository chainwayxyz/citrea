// SPDX-License-Identifier: MIT

// solc --abi --bin SimpleProxy.sol -o . --overwrite
pragma solidity ^0.8.0;

/**
 * @title SimpleProxy
 * @notice A minimal proxy contract that delegates all calls to an implementation contract.
 * This is used to test gas estimation with EIP-7702 when delegated code makes calls
 * to proxy contracts that themselves use DELEGATECALL.
 */
contract SimpleProxy {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice Function that always reverts (for testing EIP-7702 gas estimation)
     * @dev Mimics ERC-7579 execute(bytes32,bytes) signature that was in the real failing transaction
     */
    function revertingExecute(bytes32, bytes calldata) external pure {
        revert("Execution failed");
    }

    /**
     * @notice Executes a call by delegating to the implementation contract
     * @dev This explicitly delegates, similar to fallback but as a named function
     */
    function execute(bytes32, bytes calldata) external payable returns (bytes memory) {
        address impl = implementation;

        assembly {
            // Copy calldata to memory
            calldatacopy(0, 0, calldatasize())

            // Delegate call to implementation
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)

            // Copy return data to memory
            returndatacopy(0, 0, returndatasize())

            // Return or revert based on result
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
