// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import "bitcoin-spv/solidity/contracts/ValidateSPV.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";
import "../lib/WitnessUtils.sol";
import "openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";

/// @title Clementine actor registry for operator and watchtower coordination
/// @author Citrea
contract ClementineActors is Initializable, Ownable2StepUpgradeable {
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

    enum ActorStatus {
        Unknown,
        Candidate,
        Active,
        Disabled
    }

    enum ActorType {
        Operator,
        Watchtower
    }

    struct ActorSet {
        bytes32[] known;
        bytes32[] active;
        mapping(bytes32 => ActorStatus) status;
    }

    address public constant SCHNORR_VERIFIER_PRECOMPILE = address(0x200);

    bytes public constant EPOCH = hex"00";
    bytes public constant SIGHASH_DEFAULT_HASH_TYPE = hex"00";
    bytes public constant SPEND_TYPE_EXT = hex"02";
    bytes public constant INPUT_INDEX = hex"00000000";
    bytes public constant KEY_VERSION = hex"00";
    bytes public constant CODESEP_POS = hex"ffffffff";
    uint256 public constant MAX_ACTIVE_OPERATORS = 1_000;
    uint256 public constant MAX_ACTIVE_WATCHTOWERS = 1_000;
    uint256 public constant MAX_SECURITY_COUNCIL = 100;

    address public maintainer;
    uint256 public circuitVersion;
    uint256 public securityCouncilThreshold;
    uint256 public setupGeneration;
    bool public signingPaused;

    bytes32[] public securityCouncil;

    ActorSet internal operators;
    ActorSet internal watchtowers;

    mapping(bytes32 => mapping(bytes32 => uint256)) internal garbledSetupGenerations;

    event MaintainerUpdated(address oldMaintainer, address newMaintainer);
    event SigningPauseUpdated(bool signingPaused);
    event CircuitVersionUpdated(uint256 oldCircuitVersion, uint256 newCircuitVersion);
    event SecurityCouncilUpdated(uint256 threshold, bytes32[] members);
    event CandidateOperatorsAdded(bytes32[] operatorKeys, uint256 startIndex);
    event CandidateWatchtowersAdded(bytes32[] watchtowerKeys, uint256 startIndex);
    event GarbledSetupProven(
        bytes32 operatorKey, bytes32 watchtowerKey, bytes32 wtxId, bytes32 txId, uint256 setupGeneration
    );
    event ActiveActorsSet(bytes32[] operators, bytes32[] watchtowers);
    event ActiveOperatorsAdded(bytes32[] operatorKeys, uint256 startIndex);
    event ActiveWatchtowersAdded(bytes32[] watchtowerKeys, uint256 startIndex);
    event OperatorDisabled(bytes32 operatorKey);
    event WatchtowerDisabled(bytes32 watchtowerKey);
    event OperatorReinstated(bytes32 operatorKey);
    event WatchtowerReinstated(bytes32 watchtowerKey);

    modifier onlyMaintainer() {
        require(msg.sender == maintainer, "caller is not the maintainer");
        _;
    }

    modifier onlyOwnerOrMaintainer() {
        require(msg.sender == owner() || msg.sender == maintainer, "caller is not the owner or maintainer");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _maintainer,
        uint256 _circuitVersion,
        uint256 _securityCouncilThreshold,
        bytes32[] calldata _securityCouncil
    ) external initializer {
        require(_maintainer != address(0), "Maintainer cannot be zero address");

        __Ownable_init(_owner);
        __Ownable2Step_init();

        maintainer = _maintainer;
        setupGeneration = 1;
        signingPaused = true;

        _setCircuitVersion(_circuitVersion);
        _setSecurityCouncil(_securityCouncilThreshold, _securityCouncil);

        emit MaintainerUpdated(address(0), _maintainer);
        emit SigningPauseUpdated(true);
    }

    function pauseSigning() external onlyOwnerOrMaintainer {
        signingPaused = true;
        emit SigningPauseUpdated(true);
    }

    function unpauseSigning() external onlyOwnerOrMaintainer {
        require(operators.active.length != 0, "No active operators");
        require(watchtowers.active.length != 0, "No active watchtowers");
        signingPaused = false;
        emit SigningPauseUpdated(false);
    }

    function setMaintainer(address _maintainer) external onlyOwner {
        require(_maintainer != address(0), "Maintainer cannot be zero address");
        address oldMaintainer = maintainer;
        maintainer = _maintainer;
        emit MaintainerUpdated(oldMaintainer, _maintainer);
    }

    function setCircuitVersion(uint256 _circuitVersion) external onlyOwner {
        _setCircuitVersion(_circuitVersion);
        _resetSigningState();
    }

    function setSecurityCouncil(
        uint256 _securityCouncilThreshold,
        bytes32[] calldata _securityCouncil
    ) external onlyOwner {
        _setSecurityCouncil(_securityCouncilThreshold, _securityCouncil);
        _resetSigningState();
    }

    function addCandidateOperators(bytes32[] calldata operatorKeys) external onlyMaintainer {
        uint256 startIndex = _addCandidates(operators, operatorKeys);
        emit CandidateOperatorsAdded(operatorKeys, startIndex);
    }

    function addCandidateWatchtowers(bytes32[] calldata watchtowerKeys) external onlyMaintainer {
        uint256 startIndex = _addCandidates(watchtowers, watchtowerKeys);
        emit CandidateWatchtowersAdded(watchtowerKeys, startIndex);
    }

    function proveGarbledSetup(
        Transaction calldata circuitGeneratedTx,
        bytes32 operatorKey,
        bytes32 watchtowerKey,
        uint256 sourceUtxoValueSats,
        bytes calldata operatorCollateralOutpoint,
        bytes32 shaScriptPubkeys
    ) external {
        ActorStatus operatorStatus_ = operators.status[operatorKey];
        ActorStatus watchtowerStatus_ = watchtowers.status[watchtowerKey];
        require(_isCandidateOrActive(operatorStatus_), "Operator is not candidate or active");
        require(_isCandidateOrActive(watchtowerStatus_), "Watchtower is not candidate or active");
        require(!garbledSetups(operatorKey, watchtowerKey), "Garbled setup already proven");
        require(operatorCollateralOutpoint.length == 36, "Invalid collateral outpoint");

        (bytes32 wtxId, uint256 nIns) = _validateTransaction(circuitGeneratedTx);
        require(nIns == 1, "Only one input allowed");

        bytes memory input = circuitGeneratedTx.vin.extractInputAtIndex(0);
        bytes memory outputs = _stripTxVectorCount(circuitGeneratedTx.vout);
        bytes memory witness0 = WitnessUtils.extractWitnessAtIndex(circuitGeneratedTx.witness, 0);

        (, uint256 nItems) = BTCUtils.parseVarInt(witness0);
        require(nItems == 4, "Invalid witness items");

        bytes memory script = witness0.extractItemFromWitness(2);
        bytes memory expectedScript = _validateCircuitGeneratedScript(
            script, operatorKey, watchtowerKey, operatorCollateralOutpoint
        );
        _verifyCircuitGeneratedSignatures(
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

    function setActiveActors(bytes32[] calldata operatorKeys, bytes32[] calldata watchtowerKeys)
        external
        onlyMaintainer
    {
        require(operators.active.length == 0 && watchtowers.active.length == 0, "Active actors already set");
        require(operatorKeys.length != 0, "Active operators cannot be empty");
        require(watchtowerKeys.length != 0, "Active watchtowers cannot be empty");
        require(operatorKeys.length <= MAX_ACTIVE_OPERATORS, "Too many active operators");
        require(watchtowerKeys.length <= MAX_ACTIVE_WATCHTOWERS, "Too many active watchtowers");

        for (uint256 i = 0; i < operatorKeys.length; i++) {
            bytes32 operatorKey = operatorKeys[i];
            _requireCandidate(operators, operatorKey);

            for (uint256 j = 0; j < watchtowerKeys.length; j++) {
                bytes32 watchtowerKey = watchtowerKeys[j];
                require(garbledSetups(operatorKey, watchtowerKey), "Missing garbled setup");
            }

            _activate(operators, operatorKey);
        }

        for (uint256 i = 0; i < watchtowerKeys.length; i++) {
            bytes32 watchtowerKey = watchtowerKeys[i];
            _requireCandidate(watchtowers, watchtowerKey);
            _activate(watchtowers, watchtowerKey);
        }

        _pauseSigning();
        emit ActiveActorsSet(operatorKeys, watchtowerKeys);
    }

    function addActiveOperators(bytes32[] calldata operatorKeys) external onlyMaintainer {
        uint256 startIndex =
            _addActive(operators, watchtowers, operatorKeys, MAX_ACTIVE_OPERATORS, ActorType.Operator);
        emit ActiveOperatorsAdded(operatorKeys, startIndex);
    }

    function addActiveWatchtowers(bytes32[] calldata watchtowerKeys) external onlyMaintainer {
        uint256 startIndex =
            _addActive(watchtowers, operators, watchtowerKeys, MAX_ACTIVE_WATCHTOWERS, ActorType.Watchtower);
        emit ActiveWatchtowersAdded(watchtowerKeys, startIndex);
    }

    function disableOperator(bytes32 operatorKey) external onlyOwner {
        _disableActor(operators, operatorKey);
        emit OperatorDisabled(operatorKey);
    }

    function disableWatchtower(bytes32 watchtowerKey) external onlyOwner {
        _disableActor(watchtowers, watchtowerKey);
        emit WatchtowerDisabled(watchtowerKey);
    }

    function reinstateOperator(bytes32 operatorKey) external onlyOwner {
        _reinstate(operators, operatorKey);
        emit OperatorReinstated(operatorKey);
    }

    function reinstateWatchtower(bytes32 watchtowerKey) external onlyOwner {
        _reinstate(watchtowers, watchtowerKey);
        emit WatchtowerReinstated(watchtowerKey);
    }

    function getSecurityCouncil() external view returns (bytes32[] memory) {
        return securityCouncil;
    }

    function getKnownOperators() external view returns (bytes32[] memory) {
        return operators.known;
    }

    function getKnownWatchtowers() external view returns (bytes32[] memory) {
        return watchtowers.known;
    }

    function getActiveOperators() external view returns (bytes32[] memory) {
        return operators.active;
    }

    function getActiveWatchtowers() external view returns (bytes32[] memory) {
        return watchtowers.active;
    }

    function operatorStatus(bytes32 operatorKey) external view returns (ActorStatus) {
        return operators.status[operatorKey];
    }

    function watchtowerStatus(bytes32 watchtowerKey) external view returns (ActorStatus) {
        return watchtowers.status[watchtowerKey];
    }

    function isCandidateOperator(bytes32 operatorKey) external view returns (bool) {
        return operators.status[operatorKey] == ActorStatus.Candidate;
    }

    function isCandidateWatchtower(bytes32 watchtowerKey) external view returns (bool) {
        return watchtowers.status[watchtowerKey] == ActorStatus.Candidate;
    }

    function isActiveOperator(bytes32 operatorKey) external view returns (bool) {
        return operators.status[operatorKey] == ActorStatus.Active;
    }

    function isActiveWatchtower(bytes32 watchtowerKey) external view returns (bool) {
        return watchtowers.status[watchtowerKey] == ActorStatus.Active;
    }

    function isDisabledOperator(bytes32 operatorKey) external view returns (bool) {
        return operators.status[operatorKey] == ActorStatus.Disabled;
    }

    function isDisabledWatchtower(bytes32 watchtowerKey) external view returns (bool) {
        return watchtowers.status[watchtowerKey] == ActorStatus.Disabled;
    }

    function garbledSetups(bytes32 operatorKey, bytes32 watchtowerKey) public view returns (bool) {
        return setupGeneration != 0 && garbledSetupGenerations[operatorKey][watchtowerKey] == setupGeneration;
    }

    function _isCandidateOrActive(ActorStatus status) internal pure returns (bool) {
        return status == ActorStatus.Candidate || status == ActorStatus.Active;
    }

    function _setCircuitVersion(uint256 _circuitVersion) internal {
        uint256 oldCircuitVersion = circuitVersion;
        require(_circuitVersion != oldCircuitVersion, "Circuit version unchanged");
        require(_circuitVersion != 0, "Circuit version cannot be 0");
        require(_circuitVersion <= type(uint16).max, "Circuit version too large");
        circuitVersion = _circuitVersion;
        emit CircuitVersionUpdated(oldCircuitVersion, _circuitVersion);
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
        _clearActiveActors();
        _pauseSigning();
    }

    function _pauseSigning() internal {
        if (!signingPaused) {
            signingPaused = true;
            emit SigningPauseUpdated(true);
        }
    }

    function _clearActiveActors() internal {
        _clearActive(operators);
        _clearActive(watchtowers);
    }

    function _clearActive(ActorSet storage set) internal {
        for (uint256 i = 0; i < set.active.length; i++) {
            set.status[set.active[i]] = ActorStatus.Candidate;
        }
        delete set.active;
    }

    function _addCandidates(ActorSet storage set, bytes32[] calldata keys) internal returns (uint256 startIndex) {
        startIndex = set.known.length;

        for (uint256 i = 0; i < keys.length; i++) {
            bytes32 key = keys[i];
            require(key != bytes32(0), "Actor key cannot be empty");
            require(set.status[key] == ActorStatus.Unknown, "Candidate already exists");

            set.status[key] = ActorStatus.Candidate;
            set.known.push(key);
        }
    }

    function _addActive(
        ActorSet storage set,
        ActorSet storage counterparties,
        bytes32[] calldata keys,
        uint256 maxActive,
        ActorType actorType
    ) internal returns (uint256 startIndex) {
        require(counterparties.active.length != 0, "No active counterparties");
        startIndex = set.active.length;
        require(startIndex + keys.length <= maxActive, "Too many active actors");

        for (uint256 i = 0; i < keys.length; i++) {
            bytes32 key = keys[i];
            _requireCandidate(set, key);

            for (uint256 j = 0; j < counterparties.active.length; j++) {
                require(_hasGarbledSetup(actorType, key, counterparties.active[j]), "Missing garbled setup");
            }

            _activate(set, key);
        }
        _pauseSigning();
    }

    function _hasGarbledSetup(ActorType actorType, bytes32 key, bytes32 counterparty) internal view returns (bool) {
        return actorType == ActorType.Operator ? garbledSetups(key, counterparty) : garbledSetups(counterparty, key);
    }

    function _requireCandidate(ActorSet storage set, bytes32 key) internal view {
        require(set.status[key] == ActorStatus.Candidate, "Actor is not candidate");
    }

    function _activate(ActorSet storage set, bytes32 key) internal {
        set.status[key] = ActorStatus.Active;
        set.active.push(key);
    }

    function _disableActor(ActorSet storage set, bytes32 key) internal {
        require(set.status[key] == ActorStatus.Active, "Actor is not active");
        set.status[key] = ActorStatus.Disabled;
        _removeKey(set.active, key);
        _pauseSigning();
    }

    function _reinstate(ActorSet storage set, bytes32 key) internal {
        require(set.status[key] == ActorStatus.Disabled, "Actor is not disabled");
        set.status[key] = ActorStatus.Candidate;
    }

    function _recordGarbledSetup(bytes32 operatorKey, bytes32 watchtowerKey) internal {
        garbledSetupGenerations[operatorKey][watchtowerKey] = setupGeneration;
    }

    function _removeKey(bytes32[] storage values, bytes32 key) internal {
        for (uint256 i = 0; i < values.length; i++) {
            if (values[i] == key) {
                values[i] = values[values.length - 1];
                values.pop();
                return;
            }
        }
    }

    function _validateTransaction(Transaction calldata txn) internal view returns (bytes32, uint256) {
        require(txn.flag == hex"0001", "Invalid segwit flag");
        bytes32 wtxId = WitnessUtils.calculateWtxId(txn.version, txn.flag, txn.vin, txn.vout, txn.witness, txn.locktime);
        require(BTCUtils.validateVin(txn.vin), "Vin is not properly formatted");
        require(BTCUtils.validateVout(txn.vout), "Vout is not properly formatted");

        (, uint256 nIns) = BTCUtils.parseVarInt(txn.vin);
        require(WitnessUtils.validateWitness(txn.witness, nIns), "Witness is not properly formatted");

        return (wtxId, nIns);
    }

    function _validateCircuitGeneratedScript(
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

        bytes memory expectedScript = _buildCircuitGeneratedScript(operatorKey, watchtowerKey, operatorCollateralOutpoint);
        expectedScriptWithLen = abi.encodePacked(_compactSize(expectedScript.length), expectedScript);
        require(scriptWithLen.length == expectedScriptWithLen.length, "Invalid circuit script length");
        require(keccak256(scriptWithLen) == keccak256(expectedScriptWithLen), "Invalid circuit script");
    }

    function _verifyCircuitGeneratedSignatures(
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
        require(controlBlock.length > 1, "Invalid control block");
        bytes1 leafVersion = controlBlock[1] & 0xFE;
        bytes32 tapleafHash = _taggedHash("TapLeaf", abi.encodePacked(leafVersion, scriptWithLen));
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
        bytes32 messageHash = _taggedHash("TapSighash", message);

        _verifyWitnessSignature(witness0, 1, watchtowerKey, messageHash);
        _verifyWitnessSignature(witness0, 0, operatorKey, messageHash);
    }

    function _verifyWitnessSignature(bytes memory witness0, uint256 itemIndex, bytes32 pubKey, bytes32 messageHash)
        internal
        view
    {
        bytes memory signatureWithLen = witness0.extractItemFromWitness(itemIndex);
        bytes memory signature = signatureWithLen.slice(1, signatureWithLen.length - 1);
        require(_isSchnorrSigValid(abi.encodePacked(pubKey), messageHash, signature), "Invalid signature");
    }

    function _stripTxVectorCount(bytes memory vector) internal pure returns (bytes memory) {
        (uint256 varIntDataLen,) = BTCUtils.parseVarInt(vector);
        require(varIntDataLen != BTCUtils.ERR_BAD_ARG, "Bad tx vector length");
        uint256 offset = 1 + varIntDataLen;
        return vector.slice(offset, vector.length - offset);
    }

    function _buildCircuitGeneratedScript(
        bytes32 operatorKey,
        bytes32 watchtowerKey,
        bytes calldata operatorCollateralOutpoint
    ) internal view returns (bytes memory) {
        bytes memory securityCouncilScript = _buildSecurityCouncilScript();
        return abi.encodePacked(
            hex"20",
            watchtowerKey,
            hex"ad20",
            operatorKey,
            hex"ad51006302",
            _uint16LE(circuitVersion),
            hex"24",
            operatorCollateralOutpoint,
            securityCouncilScript,
            hex"68"
        );
    }

    function _buildSecurityCouncilScript() internal view returns (bytes memory script) {
        script = abi.encodePacked(
            _scriptPush(_uint32LE(securityCouncilThreshold)),
            _scriptPush(_uint32LE(securityCouncil.length))
        );
        for (uint256 i = 0; i < securityCouncil.length; i++) {
            script = abi.encodePacked(script, _scriptPush(abi.encodePacked(securityCouncil[i])));
        }
    }

    function _scriptPush(bytes memory value) internal pure returns (bytes memory) {
        if (value.length <= 75) {
            return abi.encodePacked(bytes1(uint8(value.length)), value);
        }
        if (value.length <= type(uint8).max) {
            return abi.encodePacked(hex"4c", bytes1(uint8(value.length)), value);
        }
        require(value.length <= type(uint16).max, "Script push too large");
        return abi.encodePacked(hex"4d", _uint16LE(value.length), value);
    }

    function _compactSize(uint256 value) internal pure returns (bytes memory) {
        if (value < 0xfd) {
            return abi.encodePacked(bytes1(uint8(value)));
        }
        require(value <= type(uint16).max, "Compact size too large");
        return abi.encodePacked(hex"fd", _uint16LE(value));
    }

    function _uint16LE(uint256 value) internal pure returns (bytes memory) {
        require(value <= type(uint16).max, "Value too large");
        return abi.encodePacked(bytes2(BTCUtils.reverseUint16(uint16(value))));
    }

    function _uint32LE(uint256 value) internal pure returns (bytes memory) {
        require(value <= type(uint32).max, "Value too large");
        return abi.encodePacked(bytes4(BTCUtils.reverseUint32(uint32(value))));
    }

    function _isSchnorrSigValid(bytes memory pubKey, bytes32 messageHash, bytes memory signature)
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

    function _taggedHash(string memory tag, bytes memory message) internal pure returns (bytes32) {
        bytes32 tagHash = sha256(bytes(tag));
        return sha256(abi.encodePacked(tagHash, tagHash, message));
    }
}
