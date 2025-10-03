// SPDX-License-Identifier: LGPL-3.0-or-later
pragma solidity ^0.8.4;

/** @title WitnessUtils */
/** @author Citrea, modified from Bitcoin-SPV */

import {BytesLib} from "bitcoin-spv/solidity/contracts/BytesLib.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";

library WitnessUtils {
    using BytesLib for bytes;
    using BTCUtils for bytes;

    function calculateWtxId(
        bytes4 version,
        bytes2 flag,
        bytes calldata vin,
        bytes calldata vout,
        bytes calldata witness,
        bytes4 locktime
    ) internal view returns (bytes32) {
        return abi.encodePacked(version, flag, vin, vout, witness, locktime).hash256View();
    }

    /// @notice      Checks that the witness passed up is properly formatted
    /// @param _witness  Raw bytes length-prefixed witness vector
    /// @param _nWits    The number of witnesses expected, sourced from number of inputs
    /// @return      True if it represents a validly formatted witness
    function validateWitness(bytes memory _witness, uint256 _nWits) internal pure returns (bool) {
        // Not valid if it says there are no witnesses
        if (_nWits == 0) {
            return false;
        }

        uint256 _offset = 0;

        for (uint256 i = 0; i < _nWits; i++) {
            // If we're at the end, but still expect more
            if (_offset >= _witness.length) {
                return false;
            }

            // Grab the next input and determine its length.
            uint256 _nextLen = determineWitnessLengthAt(_witness, _offset);
            if (_nextLen == BTCUtils.ERR_BAD_ARG) {
                return false;
            }

            // Increase the offset by that much
            _offset += _nextLen;
        }

        // Returns false if we're not exactly at the end
        return _offset == _witness.length;
    }

    /// @notice          Determines the length of a witness,
    ///                  starting at the specified position
    /// @param _witness  The byte array containing the witness vector
    /// @param _at       The position of the witness in the array
    /// @return          The length of the witness in bytes
    function determineWitnessLengthAt(bytes memory _witness, uint256 _at) internal pure returns (uint256) {
        uint256 _varIntDataLen;
        uint256 _nStackItems;
        
        (_varIntDataLen, _nStackItems) = BTCUtils.parseVarIntAt(_witness, _at);
        if (_varIntDataLen == BTCUtils.ERR_BAD_ARG) {
            return BTCUtils.ERR_BAD_ARG;
        }

        uint256 _itemLen;
        uint256 _offset = 1 + _varIntDataLen;

        for (uint256 i = 0; i < _nStackItems; i++) {
            (_varIntDataLen, _itemLen) = BTCUtils.parseVarIntAt(_witness, _at + _offset);
            if (_varIntDataLen == BTCUtils.ERR_BAD_ARG) {
                return BTCUtils.ERR_BAD_ARG;
            }

            _offset += 1 + _varIntDataLen + _itemLen;
        }

        return _offset;
    }

    /// @notice          Extracts the witness at a given index in the witnesses vector
    /// @dev             Iterates over the witness. If you need to extract multiple, write a custom function
    /// @param _witness  The witness vector to extract from
    /// @param _index    The 0-indexed location of the witness to extract
    /// @return          The specified witness
    function extractWitnessAtIndex(bytes memory _witness, uint256 _index) internal pure returns (bytes memory) {
        uint256 _len = 0;
        uint256 _offset = 0;

        for (uint256 _i = 0; _i < _index; _i ++) {
            _len = determineWitnessLengthAt(_witness, _offset);
            require(_len != BTCUtils.ERR_BAD_ARG, "Bad VarInt in witness");
            _offset += _len;
        }

        _len = determineWitnessLengthAt(_witness, _offset);
        require(_len != BTCUtils.ERR_BAD_ARG, "Bad VarInt in witness");
        return _witness.slice(_offset, _len);
    }

    /// @notice           Extracts the item at a given index in the witness
    /// @dev              Iterates over the items. If you need to extract multiple, write a custom function
    /// @param _witness   The witness to extract from
    /// @param _index     The 0-indexed location of the item to extract
    /// @return           The specified item
    function extractItemFromWitness(bytes memory _witness, uint256 _index) internal pure returns (bytes memory) {
        uint256 _varIntDataLen;
        uint256 _nItems;
        
        (_varIntDataLen, _nItems) = BTCUtils.parseVarInt(_witness);
        require(_varIntDataLen != BTCUtils.ERR_BAD_ARG, "Read overrun during VarInt parsing");
        require(_index < _nItems, "Witness read overrun");

        uint256 _itemLen = 0;
        uint256 _offset = 1 + _varIntDataLen;

        for (uint256 i = 0; i < _index; i++) {
            (_varIntDataLen, _itemLen) = BTCUtils.parseVarIntAt(_witness, _offset);
            require(_varIntDataLen != BTCUtils.ERR_BAD_ARG, "Bad VarInt in item");
            _offset += 1 + _varIntDataLen + _itemLen;
        }

        (_varIntDataLen, _itemLen) = BTCUtils.parseVarIntAt(_witness, _offset);
        require(_varIntDataLen != BTCUtils.ERR_BAD_ARG, "Bad VarInt in item");
        return _witness.slice(_offset, _itemLen + _varIntDataLen + 1);
    }
}
