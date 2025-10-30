// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Compile with: solc --abi --bin SimpleTokenProxy.sol --overwrite -o .

/**
 * @title SimpleTokenProxy
 * @dev Proxy contract for ERC20 that delegates calls to an implementation contract
 * This proxy stores the state (balances, allowances, totalSupply) while delegating
 * function execution to the implementation contract.
 */
contract SimpleTokenProxy {
    // Implementation contract address
    address public implementation;

    // ERC20 state variables stored in the proxy
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    uint256 public totalSupply;

    /**
     * @dev Constructor initializes the proxy with implementation address and initial token supply
     * @param _implementation Address of the implementation contract
     * @param initialSupply Initial supply of tokens allocated to the deployer
     */
    constructor(address _implementation, uint256 initialSupply) {
        require(_implementation != address(0), "Implementation address cannot be zero");
        implementation = _implementation;
        totalSupply = initialSupply;
        balances[msg.sender] = initialSupply;
    }

    /**
     * @dev Fallback function delegates all calls to the implementation contract
     * Uses inline assembly to perform delegatecall and properly return data or revert
     */
    fallback() external payable {
        address impl = implementation;
        assembly {
            // Copy calldata to memory
            calldatacopy(0, 0, calldatasize())

            // Perform delegatecall to implementation
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)

            // Copy return data to memory
            returndatacopy(0, 0, returndatasize())

            // Check delegatecall result and return or revert accordingly
            switch result
            case 0 {
                // Delegatecall failed, revert with error data
                revert(0, returndatasize())
            }
            default {
                // Delegatecall succeeded, return with data
                return(0, returndatasize())
            }
        }
    }

    /**
     * @dev Receive function allows the contract to receive ETH
     */
    receive() external payable {}
}