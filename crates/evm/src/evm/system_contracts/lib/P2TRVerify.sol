// SPDX-License-Identifier: LGPL-3.0-or-later
pragma solidity ^0.8.4;

import "bitcoin-spv/solidity/contracts/ValidateSPV.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";
import "./WitnessUtils.sol";

/** @title P2TRVerify */
/** @author Citrea */

library P2TRVerify {
    using BTCUtils for bytes;
    using WitnessUtils for bytes;
    using BytesLib for bytes;

    struct TransactionParams {
        bytes4 version;
        bytes2 flag;
        bytes vin;
        bytes vout;
        bytes witness;
        bytes4 locktime;
        bytes intermediate_nodes;
        uint256 block_height;
        uint256 index;
    }

    function isP2TRSigValid(bytes32 aggregatedKey, bytes32 messageHash, bytes memory signature) internal view returns (bool isValid) {
        require(signature.length == 64, "Invalid signature length");
        (isValid, ) = address(0x200).staticcall(abi.encodePacked(aggregatedKey, messageHash, signature));
    }

    function verifySigInTx(TransactionParams calldata tp, bytes32 aggregatedKey) internal view {
        bytes memory input = tp.vin.extractInputAtIndex(0);
        bytes32 outpointDigest = sha256(input.extractOutpoint());
        bytes32 amountDigest = sha256(abi.encodePacked(input.extractValueLE()));
        bytes32 sequenceDigest = sha256(abi.encodePacked(input.extractSequenceLEWitness()));
        bytes32 outputDigest = sha256(abi.encodePacked(tp.vout.slice(1, tp.vout.length - 1)));
        bytes memory witness0 = tp.witness.extractWitnessAtIndex(0);
        bytes memory script = witness0.extractItemFromWitness(1);
        bytes memory controlBlock = witness0.extractItemFromWitness(2);
        bytes1 leafVersion = controlBlock[0] & 0xFE;
        bytes32 tapleafHash = taggedHash("TapLeaf", (abi.encodePacked(leafVersion, script)));
        bytes32 scriptPubkeyDigest = calculateScriptPubkeyDigest(controlBlock, tapleafHash);
        bytes memory message = abi.encodePacked(hex"00", hex"00", hex"03000000", hex"00000000", outpointDigest, amountDigest, scriptPubkeyDigest, sequenceDigest, outputDigest, hex"02", hex"00000000", tapleafHash, hex"00", hex"ffffffff");
        bytes32 messageHash = taggedHash("TapSighash", message);
        require(isP2TRSigValid(aggregatedKey, messageHash, witness0.extractItemFromWitness(0)), "Invalid signature");
    }

    function taggedHash(string memory tag, bytes memory message) public pure returns (bytes32) {
        bytes32 tagHash = sha256(bytes(tag));
        return sha256(abi.encodePacked(tagHash, tagHash, message));
    }

    function calculateScriptPubkeyDigest(bytes memory controlBlock, bytes32 tapleafHash) internal pure returns (bytes32) {
        
    }
}