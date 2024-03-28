pragma solidity ^0.8.0;

contract SelfDestructor {
    uint256 public x;

    function die(address payable to) public {
        selfdestruct(to);
    }

    function set(uint256 _x) public {
        x = _x;
    }

    receive() external payable {}
}
