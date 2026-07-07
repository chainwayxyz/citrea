// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import "bitcoin-spv/solidity/contracts/ValidateSPV.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";
import "../lib/WitnessUtils.sol";
import "openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";

/// @title Clementine actor registry for operator and watchtower coordination
/// @author Citrea
/// @dev This contract is intended to be deployed behind an upgradeable proxy and initialized manually.
contract ClementineActors is Ownable2StepUpgradeable {
    using BTCUtils for bytes;
    using BytesLib for bytes;
    using WitnessUtils for bytes;

    struct Transaction {
        bytes4 version;
        bytes2 flag;
        bytes vin;
        bytes vout;
        bytes witness;
        bytes4 locktime;
    }

    address public constant SCHNORR_VERIFIER_PRECOMPILE = address(0x200);

    bytes public constant EPOCH = hex"00";
    bytes public constant SIGHASH_DEFAULT_HASH_TYPE = hex"00";
    bytes public constant SPEND_TYPE_EXT = hex"02";
    bytes public constant INPUT_INDEX = hex"00000000";
    bytes public constant KEY_VERSION = hex"00";
    bytes public constant CODESEP_POS = hex"ffffffff";
    uint256 public constant MAX_ACTIVE_OPERATORS = 10_000;
    uint256 public constant MAX_ACTIVE_WATCHTOWERS = 10_000;
    uint256 public constant MAX_CANDIDATE_OPERATORS = 10_000;
    uint256 public constant MAX_CANDIDATE_WATCHTOWERS = 10_000;
    uint256 public constant MAX_SECURITY_COUNCIL = 10_000;

    bool public initialized;
    address public operator;
    bool public signingPaused;
    uint256 public circuitVersion;
    uint256 public securityCouncilThreshold;
    uint256 public setupGeneration;

    bytes32[] public securityCouncil;
    bytes32[] public candidateWatchtowers;
    bytes32[] public candidateOperators;
    bytes32[] public activeWatchtowers;
    bytes32[] public activeOperators;

    mapping(bytes32 => bool) public isCandidateWatchtower;
    mapping(bytes32 => bool) public isCandidateOperator;
    mapping(bytes32 => bool) public isActiveWatchtower;
    mapping(bytes32 => bool) public isActiveOperator;
    mapping(bytes32 => bool) public isDisabledWatchtower;
    mapping(bytes32 => bool) public isDisabledOperator;

    mapping(bytes32 => mapping(bytes32 => uint256)) internal garbledSetupGenerations;

    event OperatorUpdated(address oldOperator, address newOperator);
    event SigningPauseUpdated(bool signingPaused);
    event CircuitVersionUpdated(uint256 oldCircuitVersion, uint256 newCircuitVersion);
    event SecurityCouncilUpdated(uint256 threshold, bytes32[] members);
    event CandidateOperatorAdded(bytes32 operatorKey, uint256 index);
    event CandidateWatchtowerAdded(bytes32 watchtowerKey, uint256 index);
    event GarbledSetupProven(
        bytes32 operatorKey, bytes32 watchtowerKey, bytes32 wtxId, bytes32 txId, uint256 setupGeneration
    );
    event ActiveActorsSet(bytes32[] operators, bytes32[] watchtowers);
    event ActiveOperatorAdded(bytes32 operatorKey, uint256 index);
    event ActiveWatchtowerAdded(bytes32 watchtowerKey, uint256 index);
    event ActiveOperatorRemoved(bytes32 operatorKey);
    event ActiveWatchtowerRemoved(bytes32 watchtowerKey);
    event OperatorDisabled(bytes32 operatorKey);
    event WatchtowerDisabled(bytes32 watchtowerKey);

    modifier onlyOperator() {
        require(msg.sender == operator, "caller is not the operator");
        _;
    }

    modifier onlyOwnerOrOperator() {
        require(msg.sender == owner() || msg.sender == operator, "caller is not the owner or operator");
        _;
    }

    function initialize(
        address _owner,
        address _operator,
        uint256 _circuitVersion,
        uint256 _securityCouncilThreshold,
        bytes32[] calldata _securityCouncil
    ) external {
        require(!initialized, "Contract is already initialized");
        require(_owner != address(0), "Owner cannot be zero address");
        require(_operator != address(0), "Operator cannot be zero address");

        initialized = true;
        _transferOwnership(_owner);
        operator = _operator;
        setupGeneration = 1;
        signingPaused = true;

        _setCircuitVersion(_circuitVersion);
        _setSecurityCouncil(_securityCouncilThreshold, _securityCouncil);

        emit OperatorUpdated(address(0), _operator);
        emit SigningPauseUpdated(true);
    }

    function setOperator(address _operator) external onlyOwner {
        require(_operator != address(0), "Operator cannot be zero address");
        address oldOperator = operator;
        operator = _operator;
        emit OperatorUpdated(oldOperator, _operator);
    }

    function setSigningPause(bool _signingPaused) external onlyOwnerOrOperator {
        if (!_signingPaused) {
            require(activeOperators.length != 0, "No active operators");
            require(activeWatchtowers.length != 0, "No active watchtowers");
        }
        signingPaused = _signingPaused;
        emit SigningPauseUpdated(_signingPaused);
    }

    function setCircuitVersion(uint256 _circuitVersion) external onlyOwner {
        require(_circuitVersion != circuitVersion, "Circuit version unchanged");
        uint256 oldCircuitVersion = circuitVersion;
        _setCircuitVersion(_circuitVersion);
        _resetSigningState();
        emit CircuitVersionUpdated(oldCircuitVersion, _circuitVersion);
    }

    function setSecurityCouncil(
        uint256 _securityCouncilThreshold,
        bytes32[] calldata _securityCouncil
    ) external onlyOwner {
        _setSecurityCouncil(_securityCouncilThreshold, _securityCouncil);
        _resetSigningState();
    }

    function addCandidateOperators(bytes32[] calldata operatorKeys) external onlyOperator {
        require(
            candidateOperators.length + operatorKeys.length <= MAX_CANDIDATE_OPERATORS,
            "Too many candidate operators"
        );
        for (uint256 i = 0; i < operatorKeys.length; i++) {
            bytes32 operatorKey = operatorKeys[i];
            require(operatorKey != bytes32(0), "Operator key cannot be empty");
            require(!isDisabledOperator[operatorKey], "Operator disabled");
            require(!isCandidateOperator[operatorKey], "Candidate operator already exists");

            isCandidateOperator[operatorKey] = true;
            candidateOperators.push(operatorKey);
            emit CandidateOperatorAdded(operatorKey, candidateOperators.length - 1);
        }
    }

    function addCandidateWatchtowers(bytes32[] calldata watchtowerKeys) external onlyOperator {
        require(
            candidateWatchtowers.length + watchtowerKeys.length <= MAX_CANDIDATE_WATCHTOWERS,
            "Too many candidate watchtowers"
        );
        for (uint256 i = 0; i < watchtowerKeys.length; i++) {
            bytes32 watchtowerKey = watchtowerKeys[i];
            require(watchtowerKey != bytes32(0), "Watchtower key cannot be empty");
            require(!isDisabledWatchtower[watchtowerKey], "Watchtower disabled");
            require(!isCandidateWatchtower[watchtowerKey], "Candidate watchtower already exists");

            isCandidateWatchtower[watchtowerKey] = true;
            candidateWatchtowers.push(watchtowerKey);
            emit CandidateWatchtowerAdded(watchtowerKey, candidateWatchtowers.length - 1);
        }
    }

    function proveGarbledSetup(
        Transaction calldata circuitGeneratedTx,
        bytes32 operatorKey,
        bytes32 watchtowerKey,
        uint256 sourceUtxoValueSats,
        bytes calldata operatorCollateralOutpoint,
        bytes32 shaScriptPubkeys
    ) external {
        require(!isDisabledOperator[operatorKey], "Operator disabled");
        require(!isDisabledWatchtower[watchtowerKey], "Watchtower disabled");
        require(isCandidateOperator[operatorKey], "Operator is not candidate");
        require(isCandidateWatchtower[watchtowerKey], "Watchtower is not candidate");
        require(!garbledSetups(operatorKey, watchtowerKey), "Garbled setup already proven");
        require(operatorCollateralOutpoint.length == 36, "Invalid collateral outpoint");

        (bytes32 wtxId, uint256 nIns) = validateTransaction(circuitGeneratedTx);
        require(nIns == 1, "Only one input allowed");

        bytes memory input = circuitGeneratedTx.vin.extractInputAtIndex(0);
        bytes memory outputs = stripTxVectorCount(circuitGeneratedTx.vout);
        bytes memory witness0 = WitnessUtils.extractWitnessAtIndex(circuitGeneratedTx.witness, 0);

        (, uint256 nItems) = BTCUtils.parseVarInt(witness0);
        require(nItems == 4, "Invalid witness items");

        bytes memory script = witness0.extractItemFromWitness(2);
        bytes memory expectedScript = validateCircuitGeneratedScript(
            script, operatorKey, watchtowerKey, operatorCollateralOutpoint
        );
        verifyCircuitGeneratedSignatures(
            input,
            outputs,
            witness0,
            expectedScript,
            circuitGeneratedTx.version,
            circuitGeneratedTx.locktime,
            shaScriptPubkeys,
            sourceUtxoValueSats,
            operatorKey,
            watchtowerKey
        );

        _recordGarbledSetup(operatorKey, watchtowerKey);
        bytes32 txId = ValidateSPV.calculateTxId(
            circuitGeneratedTx.version, circuitGeneratedTx.vin, circuitGeneratedTx.vout, circuitGeneratedTx.locktime
        );
        emit GarbledSetupProven(operatorKey, watchtowerKey, wtxId, txId, setupGeneration);
    }

    function setActiveActors(bytes32[] calldata operatorKeys, bytes32[] calldata watchtowerKeys) external onlyOperator {
        require(activeOperators.length == 0 && activeWatchtowers.length == 0, "Active actors already set");
        require(operatorKeys.length != 0, "Active operators cannot be empty");
        require(watchtowerKeys.length != 0, "Active watchtowers cannot be empty");
        require(operatorKeys.length <= MAX_ACTIVE_OPERATORS, "Too many active operators");
        require(watchtowerKeys.length <= MAX_ACTIVE_WATCHTOWERS, "Too many active watchtowers");

        for (uint256 i = 0; i < operatorKeys.length; i++) {
            bytes32 operatorKey = operatorKeys[i];
            require(!isDisabledOperator[operatorKey], "Operator disabled");
            require(isCandidateOperator[operatorKey], "Operator is not candidate");
            require(!isActiveOperator[operatorKey], "Operator already active");

            for (uint256 j = 0; j < watchtowerKeys.length; j++) {
                bytes32 watchtowerKey = watchtowerKeys[j];
                require(!isDisabledWatchtower[watchtowerKey], "Watchtower disabled");
                require(isCandidateWatchtower[watchtowerKey], "Watchtower is not candidate");
                require(garbledSetups(operatorKey, watchtowerKey), "Missing garbled setup");
            }

            isActiveOperator[operatorKey] = true;
            activeOperators.push(operatorKey);
        }

        for (uint256 i = 0; i < watchtowerKeys.length; i++) {
            bytes32 watchtowerKey = watchtowerKeys[i];
            require(!isDisabledWatchtower[watchtowerKey], "Watchtower disabled");
            require(!isActiveWatchtower[watchtowerKey], "Watchtower already active");

            isActiveWatchtower[watchtowerKey] = true;
            activeWatchtowers.push(watchtowerKey);
        }

        _pauseSigning();
        emit ActiveActorsSet(operatorKeys, watchtowerKeys);
    }

    function addActiveOperators(bytes32[] calldata operatorKeys) external onlyOperator {
        require(activeWatchtowers.length != 0, "No active watchtowers");
        require(
            activeOperators.length + operatorKeys.length <= MAX_ACTIVE_OPERATORS,
            "Too many active operators"
        );

        for (uint256 i = 0; i < operatorKeys.length; i++) {
            bytes32 operatorKey = operatorKeys[i];
            require(!isDisabledOperator[operatorKey], "Operator disabled");
            require(isCandidateOperator[operatorKey], "Operator is not candidate");
            require(!isActiveOperator[operatorKey], "Operator already active");

            for (uint256 j = 0; j < activeWatchtowers.length; j++) {
                require(garbledSetups(operatorKey, activeWatchtowers[j]), "Missing garbled setup");
            }

            isActiveOperator[operatorKey] = true;
            activeOperators.push(operatorKey);
            emit ActiveOperatorAdded(operatorKey, activeOperators.length - 1);
        }
        _pauseSigning();
    }

    function addActiveWatchtowers(bytes32[] calldata watchtowerKeys) external onlyOperator {
        require(activeOperators.length != 0, "No active operators");
        require(
            activeWatchtowers.length + watchtowerKeys.length <= MAX_ACTIVE_WATCHTOWERS,
            "Too many active watchtowers"
        );

        for (uint256 i = 0; i < watchtowerKeys.length; i++) {
            bytes32 watchtowerKey = watchtowerKeys[i];
            require(!isDisabledWatchtower[watchtowerKey], "Watchtower disabled");
            require(isCandidateWatchtower[watchtowerKey], "Watchtower is not candidate");
            require(!isActiveWatchtower[watchtowerKey], "Watchtower already active");

            for (uint256 j = 0; j < activeOperators.length; j++) {
                require(garbledSetups(activeOperators[j], watchtowerKey), "Missing garbled setup");
            }

            isActiveWatchtower[watchtowerKey] = true;
            activeWatchtowers.push(watchtowerKey);
            emit ActiveWatchtowerAdded(watchtowerKey, activeWatchtowers.length - 1);
        }
        _pauseSigning();
    }

    function removeActiveOperator(bytes32 operatorKey) external onlyOwner {
        require(isActiveOperator[operatorKey], "Operator is not active");
        isActiveOperator[operatorKey] = false;
        isDisabledOperator[operatorKey] = true;
        removeKey(activeOperators, operatorKey);
        emit ActiveOperatorRemoved(operatorKey);
        emit OperatorDisabled(operatorKey);
        _pauseSigning();
    }

    function removeActiveWatchtower(bytes32 watchtowerKey) external onlyOwner {
        require(isActiveWatchtower[watchtowerKey], "Watchtower is not active");
        isActiveWatchtower[watchtowerKey] = false;
        isDisabledWatchtower[watchtowerKey] = true;
        removeKey(activeWatchtowers, watchtowerKey);
        emit ActiveWatchtowerRemoved(watchtowerKey);
        emit WatchtowerDisabled(watchtowerKey);
        _pauseSigning();
    }

    function garbledSetups(bytes32 operatorKey, bytes32 watchtowerKey) public view returns (bool) {
        return setupGeneration != 0 && garbledSetupGenerations[operatorKey][watchtowerKey] == setupGeneration;
    }

    function getSecurityCouncil() external view returns (bytes32[] memory) {
        return securityCouncil;
    }

    function getCandidateOperators() external view returns (bytes32[] memory) {
        return candidateOperators;
    }

    function getCandidateWatchtowers() external view returns (bytes32[] memory) {
        return candidateWatchtowers;
    }

    function getActiveOperators() external view returns (bytes32[] memory) {
        return activeOperators;
    }

    function getActiveWatchtowers() external view returns (bytes32[] memory) {
        return activeWatchtowers;
    }

    function _setCircuitVersion(uint256 _circuitVersion) internal {
        require(_circuitVersion != 0, "Circuit version cannot be 0");
        require(_circuitVersion <= type(uint16).max, "Circuit version too large");
        circuitVersion = _circuitVersion;
    }

    function _setSecurityCouncil(uint256 _securityCouncilThreshold, bytes32[] calldata _securityCouncil) internal {
        require(_securityCouncilThreshold != 0, "Security council threshold cannot be 0");
        require(_securityCouncil.length != 0, "Security council cannot be empty");
        require(_securityCouncil.length <= MAX_SECURITY_COUNCIL, "Security council too large");
        require(_securityCouncilThreshold <= _securityCouncil.length, "Security council threshold too high");

        for (uint256 i = 0; i < _securityCouncil.length; i++) {
            require(_securityCouncil[i] != bytes32(0), "Security council member cannot be empty");
            for (uint256 j = i + 1; j < _securityCouncil.length; j++) {
                require(_securityCouncil[i] != _securityCouncil[j], "Duplicate security council member");
            }
        }

        securityCouncilThreshold = _securityCouncilThreshold;

        delete securityCouncil;
        for (uint256 i = 0; i < _securityCouncil.length; i++) {
            securityCouncil.push(_securityCouncil[i]);
        }

        emit SecurityCouncilUpdated(_securityCouncilThreshold, _securityCouncil);
    }

    function _resetSigningState() internal {
        setupGeneration++;
        clearActiveActors();
        _pauseSigning();
    }

    function _pauseSigning() internal {
        if (!signingPaused) {
            signingPaused = true;
            emit SigningPauseUpdated(true);
        }
    }

    function clearActiveActors() internal {
        for (uint256 i = 0; i < activeOperators.length; i++) {
            isActiveOperator[activeOperators[i]] = false;
        }
        for (uint256 i = 0; i < activeWatchtowers.length; i++) {
            isActiveWatchtower[activeWatchtowers[i]] = false;
        }
        delete activeOperators;
        delete activeWatchtowers;
    }

    function _recordGarbledSetup(bytes32 operatorKey, bytes32 watchtowerKey) internal {
        garbledSetupGenerations[operatorKey][watchtowerKey] = setupGeneration;
    }

    function removeKey(bytes32[] storage values, bytes32 key) internal {
        for (uint256 i = 0; i < values.length; i++) {
            if (values[i] == key) {
                values[i] = values[values.length - 1];
                values.pop();
                return;
            }
        }
    }

    function validateTransaction(Transaction calldata txn) internal view returns (bytes32, uint256) {
        require(txn.flag == hex"0001", "Invalid segwit flag");
        bytes32 wtxId = WitnessUtils.calculateWtxId(txn.version, txn.flag, txn.vin, txn.vout, txn.witness, txn.locktime);
        require(BTCUtils.validateVin(txn.vin), "Vin is not properly formatted");
        require(BTCUtils.validateVout(txn.vout), "Vout is not properly formatted");

        (, uint256 nIns) = BTCUtils.parseVarInt(txn.vin);
        require(WitnessUtils.validateWitness(txn.witness, nIns), "Witness is not properly formatted");

        return (wtxId, nIns);
    }

    function validateCircuitGeneratedScript(
        bytes memory scriptWithLen,
        bytes32 operatorKey,
        bytes32 watchtowerKey,
        bytes calldata operatorCollateralOutpoint
    )
        internal
        view
        returns (bytes memory expectedScriptWithLen)
    {
        (uint256 varIntDataLen, uint256 scriptLen) = BTCUtils.parseVarInt(scriptWithLen);
        require(varIntDataLen != BTCUtils.ERR_BAD_ARG, "Bad circuit script length");

        uint256 offset = 1 + varIntDataLen;
        require(scriptWithLen.length == offset + scriptLen, "Invalid circuit script length");

        bytes memory expectedScript = buildCircuitGeneratedScript(operatorKey, watchtowerKey, operatorCollateralOutpoint);
        expectedScriptWithLen = abi.encodePacked(compactSize(expectedScript.length), expectedScript);
        require(scriptWithLen.length == expectedScriptWithLen.length, "Invalid circuit script length");
        require(keccak256(scriptWithLen) == keccak256(expectedScriptWithLen), "Invalid circuit script");
    }

    function verifyCircuitGeneratedSignatures(
        bytes memory input,
        bytes memory outputs,
        bytes memory witness0,
        bytes memory scriptWithLen,
        bytes4 version,
        bytes4 locktime,
        bytes32 shaScriptPubkeys,
        uint256 sourceUtxoValueSats,
        bytes32 operatorKey,
        bytes32 watchtowerKey
    ) internal view {
        require(sourceUtxoValueSats <= type(uint64).max, "Source value too large");

        bytes32 shaPrevouts = sha256(input.extractOutpoint());
        bytes32 shaAmounts = sha256(abi.encodePacked(bytes8(BTCUtils.reverseUint64(uint64(sourceUtxoValueSats)))));
        bytes32 shaSequences = sha256(abi.encodePacked(input.extractSequenceLEWitness()));
        bytes32 shaOutputs = sha256(abi.encodePacked(outputs));
        bytes memory controlBlock = witness0.extractItemFromWitness(3);
        bytes1 leafVersion = controlBlock[1] & 0xFE;
        bytes32 tapleafHash = taggedHash("TapLeaf", abi.encodePacked(leafVersion, scriptWithLen));
        bytes memory message = abi.encodePacked(
            EPOCH,
            SIGHASH_DEFAULT_HASH_TYPE,
            version,
            locktime,
            shaPrevouts,
            shaAmounts,
            shaScriptPubkeys,
            shaSequences,
            shaOutputs,
            SPEND_TYPE_EXT,
            INPUT_INDEX,
            tapleafHash,
            KEY_VERSION,
            CODESEP_POS
        );
        bytes32 messageHash = taggedHash("TapSighash", message);

        verifyWitnessSignature(witness0, 1, watchtowerKey, messageHash);
        verifyWitnessSignature(witness0, 0, operatorKey, messageHash);
    }

    function verifyWitnessSignature(bytes memory witness0, uint256 itemIndex, bytes32 pubKey, bytes32 messageHash)
        internal
        view
    {
        bytes memory signatureWithLen = witness0.extractItemFromWitness(itemIndex);
        bytes memory signature = signatureWithLen.slice(1, signatureWithLen.length - 1);
        require(isSchnorrSigValid(abi.encodePacked(pubKey), messageHash, signature), "Invalid signature");
    }

    function stripTxVectorCount(bytes memory vector) internal pure returns (bytes memory) {
        (uint256 varIntDataLen,) = BTCUtils.parseVarInt(vector);
        require(varIntDataLen != BTCUtils.ERR_BAD_ARG, "Bad tx vector length");
        uint256 offset = 1 + varIntDataLen;
        return vector.slice(offset, vector.length - offset);
    }

    function buildCircuitGeneratedScript(
        bytes32 operatorKey,
        bytes32 watchtowerKey,
        bytes calldata operatorCollateralOutpoint
    ) internal view returns (bytes memory) {
        bytes memory securityCouncilScript = buildSecurityCouncilScript();
        return abi.encodePacked(
            hex"20",
            watchtowerKey,
            hex"ad20",
            operatorKey,
            hex"ad51006302",
            uint16LE(circuitVersion),
            hex"24",
            operatorCollateralOutpoint,
            securityCouncilScript,
            hex"68"
        );
    }

    function buildSecurityCouncilScript() internal view returns (bytes memory script) {
        script = abi.encodePacked(
            scriptPush(uint32LE(securityCouncilThreshold)),
            scriptPush(uint32LE(securityCouncil.length))
        );
        for (uint256 i = 0; i < securityCouncil.length; i++) {
            script = abi.encodePacked(script, scriptPush(abi.encodePacked(securityCouncil[i])));
        }
    }

    function scriptPush(bytes memory value) internal pure returns (bytes memory) {
        if (value.length <= 75) {
            return abi.encodePacked(bytes1(uint8(value.length)), value);
        }
        if (value.length <= type(uint8).max) {
            return abi.encodePacked(hex"4c", bytes1(uint8(value.length)), value);
        }
        require(value.length <= type(uint16).max, "Script push too large");
        return abi.encodePacked(hex"4d", uint16LE(value.length), value);
    }

    function compactSize(uint256 value) internal pure returns (bytes memory) {
        if (value < 0xfd) {
            return abi.encodePacked(bytes1(uint8(value)));
        }
        require(value <= type(uint16).max, "Compact size too large");
        return abi.encodePacked(hex"fd", uint16LE(value));
    }

    function uint16LE(uint256 value) internal pure returns (bytes memory) {
        require(value <= type(uint16).max, "Value too large");
        return abi.encodePacked(bytes1(uint8(value)), bytes1(uint8(value >> 8)));
    }

    function uint32LE(uint256 value) internal pure returns (bytes memory) {
        require(value <= type(uint32).max, "Value too large");
        return abi.encodePacked(
            bytes1(uint8(value)),
            bytes1(uint8(value >> 8)),
            bytes1(uint8(value >> 16)),
            bytes1(uint8(value >> 24))
        );
    }

    function isSchnorrSigValid(bytes memory pubKey, bytes32 messageHash, bytes memory signature)
        internal
        view
        returns (bool isValid)
    {
        require(signature.length == 64 || signature.length == 65, "Invalid signature length");
        signature = signature.slice(0, 64);
        (bool success, bytes memory result) =
            address(SCHNORR_VERIFIER_PRECOMPILE).staticcall(abi.encodePacked(pubKey, messageHash, signature));
        isValid = success && (result.length == 32) && (result[31] == 0x01);
    }

    function taggedHash(string memory tag, bytes memory message) internal pure returns (bytes32) {
        bytes32 tagHash = sha256(bytes(tag));
        return sha256(abi.encodePacked(tagHash, tagHash, message));
    }
}
