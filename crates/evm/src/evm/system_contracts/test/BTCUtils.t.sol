// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Test.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";

contract BTCUtilsTest is Test {
    using BTCUtils for bytes;

    // Helper function to create a valid output structure
    // Output format: 8 bytes value + 1 byte scriptPubKey length + scriptPubKey
    function createOutput(uint64 value, bytes memory scriptPubKey) internal pure returns (bytes memory) {
        bytes memory output = new bytes(8 + 1 + scriptPubKey.length);

        // Little-endian value (8 bytes)
        for (uint i = 0; i < 8; i++) {
            output[i] = bytes1(uint8(value >> (i * 8)));
        }

        // ScriptPubKey length
        output[8] = bytes1(uint8(scriptPubKey.length));

        // ScriptPubKey
        for (uint i = 0; i < scriptPubKey.length; i++) {
            output[9 + i] = scriptPubKey[i];
        }

        return output;
    }

    // ============ Original test case from testVectors.json ============

    function test_extractOpReturnData_OriginalTestCase() public pure {
        // Test case from testVectors.json
        // Input: 0x0000000000000000166a14edb1b5c2f39af0fec151732585b1049b07895211
        // Expected output: 0xedb1b5c2f39af0fec151732585b1049b07895211
        bytes memory output = hex"0000000000000000166a14edb1b5c2f39af0fec151732585b1049b07895211";
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, hex"edb1b5c2f39af0fec151732585b1049b07895211");
    }

    // ============ OP_PUSHBYTES_N tests (0x01-0x4b) ============

    function test_extractOpReturnData_OP_PUSHBYTES_1() public pure {
        // OP_RETURN followed by OP_PUSHBYTES_1 (0x01) with 1 byte data
        bytes memory scriptPubKey = hex"6a01ff"; // OP_RETURN, PUSHBYTES_1, data
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, hex"ff");
    }

    function test_extractOpReturnData_OP_PUSHBYTES_32() public pure {
        // OP_RETURN followed by OP_PUSHBYTES_32 (0x20) with 32 bytes data
        bytes memory scriptPubKey = hex"6a200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, hex"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    }

    function test_extractOpReturnData_OP_PUSHBYTES_75() public pure {
        // OP_RETURN followed by OP_PUSHBYTES_75 (0x4b) - max for direct push
        bytes memory data = new bytes(75);
        for (uint i = 0; i < 75; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes memory scriptPubKey = abi.encodePacked(hex"6a4b", data);
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, data);
    }

    // ============ OP_PUSHDATA1 tests (0x4c) ============

    function test_extractOpReturnData_OP_PUSHDATA1_Small() public pure {
        // OP_RETURN followed by OP_PUSHDATA1 (0x4c), length byte (0x05), 5 bytes data
        bytes memory scriptPubKey = hex"6a4c050102030405";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, hex"0102030405");
    }

    function test_extractOpReturnData_OP_PUSHDATA1_76Bytes() public pure {
        // OP_PUSHDATA1 is typically used for 76-255 bytes
        bytes memory data = new bytes(76);
        for (uint i = 0; i < 76; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes memory scriptPubKey = abi.encodePacked(hex"6a4c4c", data); // OP_RETURN, OP_PUSHDATA1, length=76
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, data);
    }

    function test_extractOpReturnData_OP_PUSHDATA1_255Bytes() public pure {
        // Max size for OP_PUSHDATA1 (255 bytes)
        bytes memory data = new bytes(255);
        for (uint i = 0; i < 255; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes memory scriptPubKey = abi.encodePacked(hex"6a4cff", data); // OP_RETURN, OP_PUSHDATA1, length=255
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, data);
    }

    // ============ OP_PUSHDATA2 tests (0x4d) ============

    function test_extractOpReturnData_OP_PUSHDATA2_Small() public pure {
        // OP_RETURN followed by OP_PUSHDATA2 (0x4d), 2-byte length (little-endian), data
        // Length = 5 (0x0500 in little-endian)
        bytes memory scriptPubKey = hex"6a4d05000102030405";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, hex"0102030405");
    }

    function test_extractOpReturnData_OP_PUSHDATA2_256Bytes() public pure {
        // 256 bytes (0x0001 little-endian)
        bytes memory data = new bytes(256);
        for (uint i = 0; i < 256; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes memory scriptPubKey = abi.encodePacked(hex"6a4d0001", data); // length = 256 = 0x0100 LE
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, data);
    }

    // ============ OP_PUSHDATA4 tests (0x4e) ============

    function test_extractOpReturnData_OP_PUSHDATA4_Small() public pure {
        // OP_RETURN followed by OP_PUSHDATA4 (0x4e), 4-byte length (little-endian), data
        // Length = 5 (0x05000000 in little-endian)
        bytes memory scriptPubKey = hex"6a4e050000000102030405";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, hex"0102030405");
    }

    // ============ OP_0 test (0x00) ============

    function test_extractOpReturnData_OP_0() public pure {
        // OP_RETURN followed by OP_0 (0x00) - pushes empty byte sequence
        bytes memory scriptPubKey = hex"6a00";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 0);
    }

    // ============ OP_1NEGATE test (0x4f) ============

    function test_extractOpReturnData_OP_1NEGATE() public pure {
        // OP_RETURN followed by OP_1NEGATE (0x4f) - pushes -1 (0x81)
        bytes memory scriptPubKey = hex"6a4f";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 1);
        assertEq(result[0], bytes1(0x81));
    }

    // ============ OP_1 through OP_16 tests (0x51-0x60) ============

    function test_extractOpReturnData_OP_1() public pure {
        // OP_RETURN followed by OP_1 (0x51) - pushes 1
        bytes memory scriptPubKey = hex"6a51";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 1);
        assertEq(result[0], bytes1(0x01));
    }

    function test_extractOpReturnData_OP_5() public pure {
        // OP_RETURN followed by OP_5 (0x55) - pushes 5
        bytes memory scriptPubKey = hex"6a55";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 1);
        assertEq(result[0], bytes1(0x05));
    }

    function test_extractOpReturnData_OP_16() public pure {
        // OP_RETURN followed by OP_16 (0x60) - pushes 16
        bytes memory scriptPubKey = hex"6a60";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 1);
        assertEq(result[0], bytes1(0x10));
    }

    // ============ Edge case tests ============

    function test_extractOpReturnData_NotOpReturn() public pure {
        // Not an OP_RETURN output (P2PKH)
        bytes memory output = hex"4897070000000000220020a4333e5612ab1a1043b25755c89b16d55184a42f81799e623e6bc39db8539c18";
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 0);
    }

    function test_extractOpReturnData_EmptyOpReturn() public pure {
        // OP_RETURN with no data (just the OP_RETURN opcode)
        bytes memory scriptPubKey = hex"6a";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 0);
    }

    function test_extractOpReturnData_TooShort() public pure {
        // Output too short to be valid
        bytes memory output = hex"0000000000000000";
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 0);
    }

    function test_extractOpReturnData_TruncatedPushBytes() public pure {
        // OP_RETURN with OP_PUSHBYTES_20 but not enough data
        bytes memory output = hex"0000000000000000166a14edb1b5c2f39af0fec151732585b1049b078952";
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 0); // Should return empty due to insufficient data
    }

    function test_extractOpReturnData_TruncatedPushData1() public pure {
        // OP_RETURN with OP_PUSHDATA1 but missing length byte
        bytes memory scriptPubKey = hex"6a4c"; // OP_RETURN, OP_PUSHDATA1, no length
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 0);
    }

    function test_extractOpReturnData_TruncatedPushData2() public pure {
        // OP_RETURN with OP_PUSHDATA2 but only 1 length byte
        bytes memory scriptPubKey = hex"6a4d05"; // OP_RETURN, OP_PUSHDATA2, only 1 byte of length
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 0);
    }

    function test_extractOpReturnData_TruncatedPushData4() public pure {
        // OP_RETURN with OP_PUSHDATA4 but only 2 length bytes
        bytes memory scriptPubKey = hex"6a4e0500"; // OP_RETURN, OP_PUSHDATA4, only 2 bytes of length
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 0);
    }

    function test_extractOpReturnData_OP_RESERVED() public pure {
        // OP_RETURN followed by OP_RESERVED (0x50) - should return empty
        bytes memory scriptPubKey = hex"6a50";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 0);
    }

    function test_extractOpReturnData_UnknownOpcode() public pure {
        // OP_RETURN followed by unknown opcode (e.g., 0x61 which is OP_NOP)
        bytes memory scriptPubKey = hex"6a61";
        bytes memory output = createOutput(0, scriptPubKey);
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result.length, 0);
    }

    function test_extractOpReturnData_NonZeroValue() public pure {
        // OP_RETURN outputs typically have 0 value, but test with non-zero
        bytes memory scriptPubKey = hex"6a14edb1b5c2f39af0fec151732585b1049b07895211";
        bytes memory output = createOutput(1000000, scriptPubKey); // 1 million satoshis
        bytes memory result = BTCUtils.extractOpReturnData(output);
        assertEq(result, hex"edb1b5c2f39af0fec151732585b1049b07895211");
    }
}
