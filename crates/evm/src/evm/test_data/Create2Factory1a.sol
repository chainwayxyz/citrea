// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Factory for test 1-a: creates, calls selfdestruct, recreates - all in ONE transaction
contract Create2Factory1a {
    event Deployed(address indexed addr, bytes32 indexed salt);

    /// @notice Deploy a contract, call its selfdestruct, then redeploy - all in same tx
    function deployDestroyRedeploy(
        bytes32 salt,
        bytes memory initCode,
        address beneficiary
    ) public returns (address) {
        // First CREATE2
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

        // Recreate at same address (same tx, so should succeed post-EIP-6780)
        address addr2;
        assembly {
            addr2 := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        require(addr2 != address(0), "RECREATE_FAILED");
        emit Deployed(addr2, salt);

        return addr2;
    }
}
