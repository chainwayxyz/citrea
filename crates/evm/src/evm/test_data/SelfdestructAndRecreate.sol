// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Contract A for test 2-a: calls selfdestruct on target, then asks factory to recreate
/// This attempts to destroy + recreate in the same transaction, but the target was created
/// in a PREVIOUS transaction, so EIP-6780 does not allow full destruction and recreation fails.
contract SelfdestructAndRecreate {
    event AttemptedRecreation(bool success, address targetAddr);

    /// @notice Calls selfdestruct on target, then calls factory to recreate
    /// @param target The contract to selfdestruct
    /// @param beneficiary Where to send the selfdestructed funds
    /// @param factory The CREATE2 factory address
    /// @param salt The salt for CREATE2
    /// @param initCode The init code for CREATE2
    function destroyAndRecreate(
        address target,
        address beneficiary,
        address factory,
        bytes32 salt,
        bytes memory initCode
    ) public returns (bool recreateSuccess, address newAddr) {
        // First, call selfdestruct on the target contract
        (bool destroySuccess, ) = target.call(
            abi.encodeWithSignature("die(address)", beneficiary)
        );
        require(destroySuccess, "SELFDESTRUCT_CALL_FAILED");

        // Now try to recreate via the factory (this should fail post-EIP-6780
        // because the target was created in a previous transaction)
        (recreateSuccess, ) = factory.call(
            abi.encodeWithSignature("deployOnly(bytes32,bytes)", salt, initCode)
        );

        // Require recreation to succeed - this will revert the whole tx if it fails
        require(recreateSuccess, "RECREATION_FAILED");

        emit AttemptedRecreation(recreateSuccess, target);

        return (recreateSuccess, target);
    }
}
