// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Factory for test 1-b: has deployAndDestroy + deployOnly functions
contract Create2Factory1b {
    event Deployed(address indexed addr, bytes32 indexed salt);

    /// @notice Deploy a contract and call its selfdestruct (in same tx as creation)
    function deployAndDestroy(
        bytes32 salt,
        bytes memory initCode,
        address beneficiary
    ) public returns (address) {
        address addr;
        assembly {
            addr := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        require(addr != address(0), "CREATE2_FAILED");
        emit Deployed(addr, salt);

        // Call selfdestruct on the created contract (same tx as creation)
        (bool success, ) = addr.call(
            abi.encodeWithSignature("die(address)", beneficiary)
        );
        require(success, "SELFDESTRUCT_CALL_FAILED");

        return addr;
    }

    /// @notice Just deploy a contract via CREATE2
    function deployOnly(bytes32 salt, bytes memory initCode) public returns (address) {
        address addr;
        assembly {
            addr := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        require(addr != address(0), "CREATE2_FAILED");
        emit Deployed(addr, salt);
        return addr;
    }
}
