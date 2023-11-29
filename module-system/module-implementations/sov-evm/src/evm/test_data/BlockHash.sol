pragma solidity ^0.8.0;

contract BlockHash {
    function getBlockHash(uint num) public view returns (bytes32 hash) {
        hash = blockhash(num);
    }
}
