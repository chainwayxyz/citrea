pragma solidity ^0.8.0;

// solc --abi --bin  Coinbase.sol  -o . --overwrite
contract Coinbase {
    // Function to reward the miner
    function rewardMiner() external payable {
        uint amount = msg.value; // The amount of Ether sent in the transaction
        require(amount > 0, "No Ether sent to reward the miner");

        // Sending the received Ether to the miner of the current block
        payable(block.coinbase).transfer(amount);
    }

    // Function to receive Ether. This is required to receive Ether into the contract
    receive() external payable {}
}
