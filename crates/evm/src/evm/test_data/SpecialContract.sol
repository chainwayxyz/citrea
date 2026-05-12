pragma solidity ^0.8.0;

contract SpecialContract {
    uint256 public x;
    uint256 public y;

    constructor() {
        x = 42;
        y = 100;
    }

    function die(address payable to) public {
        selfdestruct(to);
    }

    receive() external payable {}
}
