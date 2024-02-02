// SPDX-License-Identifier: MIT

// solc --abi --bin  Caller.sol  -o . --overwrite
pragma solidity ^0.8.0;

interface ISimpleStorage {
    function set(uint256 num) external;

    function get() external view returns (uint);
}

contract Caller {
    uint256 public num;

    function callset(address addr, uint256 num) public {
        ISimpleStorage(addr).set(num);
    }

    function callget(address addr) public view returns (uint) {
        ISimpleStorage(addr).get();
    }
}
