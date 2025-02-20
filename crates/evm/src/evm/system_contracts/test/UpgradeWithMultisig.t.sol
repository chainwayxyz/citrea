// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/BitcoinLightClient.sol";
import "openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract FalseClient is BitcoinLightClient {
    function getBlockHashFalse(uint256 /* _blockNumber */) public pure returns (bytes32) {
        return keccak256("false");
    }
}

interface ISafeFactory {
    function createProxyWithNonce(address _singleton, bytes memory initializer, uint256 saltNonce) external returns (address);
}

interface ISafe {
    enum Operation {
        Call,
        DelegateCall
    }

    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success);

    function nonce() external view returns (uint256);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);
}


contract UpgradeWithMultisigTest is Test {
    string constant CITREA_TESTNET_RPC = "https://rpc.testnet.citrea.xyz";
    address constant SAFE_FACTORY = address(0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67);
    address constant SAFE_SINGLETON = address(0x41675C099F32341bf84BFc5382aF534df5C7461a);

    ProxyAdmin proxyAdmin = ProxyAdmin(0x31fFFfFfFFFffFFFFFFfFFffffFFffffFfFFfffF);
    address constant BITCOIN_LIGHT_CLIENT = address(0x3100000000000000000000000000000000000001);
    address constant PROXY_ADMIN_OWNER = address(0x84e767448f9B4a37A3DF6f7b063F00151226307F);

    address safe;

    struct SafeTransactionParams {
        address to;
        uint256 value;
        bytes data;
        ISafe.Operation operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address refundReceiver;
    }


    function setUp() public {
        vm.createSelectFork(CITREA_TESTNET_RPC);
        vm.startPrank(PROXY_ADMIN_OWNER);
        address[] memory owners = new address[](4);

        owners[0] = vm.addr(uint256(keccak256("first_signer")));
        owners[1] = vm.addr(uint256(keccak256("second_signer")));
        owners[2] = vm.addr(uint256(keccak256("third_signer")));
        owners[3] = vm.addr(uint256(keccak256("fourth_signer")));

        uint256 threshold = 3;

        bytes memory initializer = abi.encodeWithSelector(
            ISafe.setup.selector,
            owners,
            threshold,       
            address(0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54),        
            bytes(hex"fe51f64300000000000000000000000029fcb43b46531bca003ddc8fcb67ffe91900c762"),       
            address(0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99),
            address(0),
            0,
            payable(address(0))
        );

        safe = ISafeFactory(SAFE_FACTORY).createProxyWithNonce(SAFE_SINGLETON, initializer, 0);
    }

    function testChangeUpgradeOwnerToMultisig() public {
        upgradeContractWithMultisig();
        assertEq(FalseClient(BITCOIN_LIGHT_CLIENT).getBlockHashFalse(0), keccak256("false"));
    }

    function testPastOwnerCannotUpgrade() public {
        upgradeContractWithMultisig();
        address newImpl = address(new FalseClient());
        vm.expectRevert("Ownable: caller is not the owner");
        proxyAdmin.upgrade(ITransparentUpgradeableProxy(payable(BITCOIN_LIGHT_CLIENT)), newImpl);
    }

    function prepareUpgradeParams(address newImpl) internal view returns (SafeTransactionParams memory) {
        bytes memory data = abi.encodeWithSelector(ProxyAdmin.upgrade.selector, BITCOIN_LIGHT_CLIENT, newImpl);
        return SafeTransactionParams({
            to: address(proxyAdmin),
            value: 0,
            data: data,
            operation: ISafe.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: address(0)
        });
    }

    function executeSafeTransaction(SafeTransactionParams memory params, bytes memory signatures) internal {
        ISafe(safe).execTransaction(
            params.to,
            params.value,
            params.data,
            params.operation,
            params.safeTxGas,
            params.baseGas,
            params.gasPrice,
            params.gasToken,
            payable(params.refundReceiver),
            signatures
        );
    }

    function testCannotUpgradeWithoutMeetingThreshold() public {
        address newImpl = address(new FalseClient());
        proxyAdmin.transferOwnership(safe);
        
        uint256[] memory signers = new uint256[](2);
        // Signatures are sorted by address
        signers[0] = uint256(keccak256("second_signer"));
        signers[1] = uint256(keccak256("fourth_signer"));
        
        SafeTransactionParams memory params = prepareUpgradeParams(newImpl);
        bytes memory signatures = signTransaction(
            ISafe(safe),
            signers,
            params
        );

        vm.expectRevert("GS020"); // Signatures data too short
        executeSafeTransaction(params, signatures);
    }

    function testCanUpgradeWithArbitrarySignerSet() public {
        address newImpl = address(new FalseClient());
        proxyAdmin.transferOwnership(safe);
        
        uint256[] memory signers = new uint256[](3);
        // Signatures are sorted by address
        signers[0] = uint256(keccak256("second_signer"));
        signers[1] = uint256(keccak256("first_signer"));
        signers[2] = uint256(keccak256("third_signer"));
        
        SafeTransactionParams memory params = prepareUpgradeParams(newImpl);
        bytes memory signatures = signTransaction(
            ISafe(safe),
            signers,
            params
        );

        executeSafeTransaction(params, signatures);
        assertEq(FalseClient(BITCOIN_LIGHT_CLIENT).getBlockHashFalse(0), keccak256("false"));
    }

    function upgradeContractWithMultisig() internal {
        address newImpl = address(new FalseClient());
        proxyAdmin.transferOwnership(safe);
        
        uint256[] memory signers = new uint256[](3);
        // Signatures are sorted by address
        signers[0] = uint256(keccak256("second_signer"));
        signers[1] = uint256(keccak256("fourth_signer")); 
        signers[2] = uint256(keccak256("first_signer"));
        
        SafeTransactionParams memory params = prepareUpgradeParams(newImpl);
        bytes memory signatures = signTransaction(
            ISafe(safe),
            signers,
            params
        );

        executeSafeTransaction(params, signatures);
    }

    function signTransaction(
        ISafe instance,
        uint256[] memory pks,
        SafeTransactionParams memory params
    ) internal view returns (bytes memory signatures) {
        bytes32 txDataHash = getTransactionHash(instance, params);
        
        for (uint256 i = 0; i < pks.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], txDataHash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }
        
        return signatures;
    }

    function getTransactionHash(
        ISafe instance,
        SafeTransactionParams memory params
    ) internal view returns (bytes32) {
        uint256 _nonce = instance.nonce();
        return instance.getTransactionHash(
            params.to,
            params.value,
            params.data,
            params.operation,
            params.safeTxGas,
            params.baseGas,
            params.gasPrice,
            params.gasToken,
            params.refundReceiver,
            _nonce
        );
    }
}