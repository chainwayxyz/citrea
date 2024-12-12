// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract BlobBaseFee{
    uint256 public x;
    function storeBlobBaseFee() external {
            x = block.blobbasefee;
    }
}