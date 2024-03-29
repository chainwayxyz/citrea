pragma solidity ^0.4.6;

contract Test {
    event E0();
    event E1(uint);
    event E2(uint indexed);
    event E3(address);
    event E4(address indexed);
    event E5(uint, address) anonymous;

    uint public ui;
    mapping(address => uint) map;

    function Test(uint ui_) {
        ui = ui_;
        map[msg.sender] = ui_;
    }

    function events(uint ui_, address addr_) {
        E0();
        E1(ui_);
        E2(ui_);
        E3(addr_);
        E4(addr_);
        E5(ui_, addr_);
    }

    function constFunc(
        uint a,
        uint b,
        uint c
    ) constant returns (uint, uint, uint) {
        return (a, b, c);
    }

    function getFromMap(address addr) constant returns (uint) {
        return map[addr];
    }

    function addToMap(address addr, uint value) {
        map[addr] = value;
    }
}
