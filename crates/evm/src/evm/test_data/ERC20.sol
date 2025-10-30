// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// solc --abi --bin ERC20.sol --overwrite -o .

/**
 * @title ERC20Implementation
 * @dev Basic ERC20 implementation for testing
 * Storage layout must match SimpleTokenProxy for delegatecall compatibility
 */
contract ERC20Implementation {
    // Slot 0: Reserved to match proxy's implementation address slot
    address private _unused;

    // Slot 1: balances (matches proxy slot 1)
    mapping(address => uint256) public balances;

    // Slot 2: allowances (matches proxy slot 2)
    mapping(address => mapping(address => uint256)) public allowances;

    // Slot 3: totalSupply (matches proxy slot 3)
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
}