pragma solidity ^0.8.0;

contract Logs {
    event Log(
        address indexed sender,
        address indexed contractAddress,
        string indexed senderMessage,
        string message
    );

    event AnotherLog(address indexed contractAddress);

    function publishEvent(string calldata _senderMessage) public {
        emit Log(msg.sender, address(this), _senderMessage, "Hello World!");

        emit AnotherLog(address(this));
    }
}
