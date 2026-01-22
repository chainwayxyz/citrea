// solcjs --abi --bin  CrazyKeccak.sol  -o . --overwrite

pragma solidity ^0.8.0;
contract CrazyKeccak {
    function keccak(uint256 times) external view returns (bytes32 h) {
        h = blockhash(block.number - 1); // bytes32
        for (uint256 i = 0; i < times; i++) {
            h = keccak256(abi.encodePacked(h));
        }
    }
}
