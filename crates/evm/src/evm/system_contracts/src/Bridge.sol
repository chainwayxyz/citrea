// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "bitcoin-spv/solidity/contracts/ValidateSPV.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";
import "../lib/WitnessUtils.sol";
import "./BitcoinLightClient.sol";
import "openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";

/// @title Bridge contract for the Citrea end of Citrea <> Bitcoin bridge
/// @author Citrea

contract Bridge is Ownable2StepUpgradeable {
    using BTCUtils for bytes;
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

    struct UTXO {
        bytes32 txId;
        uint32 outputId;
    }

    BitcoinLightClient public constant LIGHT_CLIENT = BitcoinLightClient(address(0x3100000000000000000000000000000000000001));
    address public constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);

    bool public initialized;
    uint256 public depositAmount;
    address public operator;
    bytes public depositScript;
    bytes public scriptSuffix;
    uint256 currentDepositId;    
    mapping(bytes32 => uint256) public txIdToDepositId;
    bool[1000] public isOperatorMalicious;
    UTXO[] public withdrawalUTXOs;
    mapping(uint256 => uint256) public withdrawFillers;
    bytes public kickoffScript;
    
    event Deposit(bytes32 wtxId, bytes32 txId, address recipient, uint256 timestamp, uint256 depositId);
    event Withdrawal(UTXO utxo, uint256 index, uint256 timestamp);
    event DepositScriptUpdate(bytes depositScript, bytes scriptSuffix);
    event OperatorUpdated(address oldOperator, address newOperator);
    event WithdrawFillerDeclared(uint256 withdrawId, uint256 withdrawFillerId);
    event MaliciousOperatorMarked(uint256 operatorId);
    event KickoffScriptUpdate(bytes kickoffScript);

    modifier onlySystem() {
        require(msg.sender == SYSTEM_CALLER, "caller is not the system caller");
        _;
    }

    modifier onlyOperator() {
        require(msg.sender == operator, "caller is not the operator");
        _;
    }

    /// @notice Initializes the bridge contract and sets the deposit script
    /// @param _depositScript The deposit script expected in the witness field for all L1 deposits 
    /// @param _scriptSuffix The suffix of the deposit script that follows the receiver address
    /// @param _depositAmount The CBTC amount that can be deposited and withdrawn
    function initialize(bytes calldata _depositScript, bytes calldata _scriptSuffix, uint256 _depositAmount) external onlySystem {
        require(!initialized, "Contract is already initialized");
        require(_depositAmount != 0, "Deposit amount cannot be 0");
        require(_depositScript.length != 0, "Deposit script cannot be empty");

        initialized = true;
        depositScript = _depositScript;
        scriptSuffix = _scriptSuffix;
        depositAmount = _depositAmount;
        
        // Set initial operator to SYSTEM_CALLER so that Citrea can get operational by starting to process deposits
        operator = SYSTEM_CALLER;

        emit OperatorUpdated(address(0), SYSTEM_CALLER);
        emit DepositScriptUpdate(_depositScript, _scriptSuffix);
    }

    /// @notice Sets the expected deposit script of the deposit transaction on Bitcoin, contained in the witness
    /// @dev Deposit script contains a fixed script that checks signatures of verifiers and pushes EVM address of the receiver
    /// @param _depositScript The new deposit script
    /// @param _scriptSuffix The part of the deposit script that succeeds the receiver address
    function setDepositScript(bytes calldata _depositScript, bytes calldata _scriptSuffix) external onlyOwner {
        require(_depositScript.length != 0, "Deposit script cannot be empty");

        depositScript = _depositScript;
        scriptSuffix = _scriptSuffix;

        emit DepositScriptUpdate(_depositScript, _scriptSuffix);
    }

    /// @notice Sets the kickoff script that is expected in the witness field of the kickoff transaction on Bitcoin
    /// @param _kickoffScript The kickoff script
    function setKickoffScript(bytes calldata _kickoffScript) external onlyOwner {
        require(_kickoffScript.length != 0, "Deposit script cannot be empty");

        kickoffScript = _kickoffScript;

        emit KickoffScriptUpdate(_kickoffScript);
    }

    /// @notice Checks if the deposit amount is sent to the bridge multisig on Bitcoin, and if so, sends the deposit amount to the receiver
    function deposit(
        TransactionParams calldata moveTp 
    ) external onlyOperator {
        // We don't need to check if the contract is initialized, as without an `initialize` call and `deposit` calls afterwards,
        // only the system caller can execute a transaction on Citrea, as no addresses have any balance. Thus there's no risk of 
        // `deposit` being called before `initialize` maliciously.
        
        (bytes32 wtxId, uint256 _nIns) = validateAndCheckInclusion(moveTp);
        require(_nIns == 1, "Only one input allowed");
        bytes32 txId = ValidateSPV.calculateTxId(moveTp.version, moveTp.vin, moveTp.vout, moveTp.locktime);

        require(txIdToDepositId[txId] == 0, "txId already spent");
        txIdToDepositId[txId] = ++currentDepositId;
        
        bytes memory witness0 = WitnessUtils.extractWitnessAtIndex(moveTp.witness, 0);
        (, uint256 _nItems) = BTCUtils.parseVarInt(witness0);
        require(_nItems == 3, "Invalid witness items"); // musig + script + witness script

        bytes memory script = WitnessUtils.extractItemFromWitness(witness0, 1); // skip musig
        uint256 _len = depositScript.length;
        bytes memory _depositScript = script.slice(0, _len);
        require(isBytesEqual(_depositScript, depositScript), "Invalid deposit script");
        bytes memory _suffix = script.slice(script.length - scriptSuffix.length, scriptSuffix.length);
        require(isBytesEqual(_suffix, scriptSuffix), "Invalid script suffix");

        address recipient = extractRecipientAddress(script);
        emit Deposit(wtxId, txId, recipient, block.timestamp, currentDepositId);

        (bool success, ) = recipient.call{value: depositAmount}("");
        require(success, "Transfer failed");
    }

    /// @notice Accepts 1 cBTC from the sender and inserts this withdrawal request of 1 BTC on Bitcoin into the withdrawals array so that later on can be processed by the operator 
    /// @param txId The txId of the withdrawal transaction on Bitcoin
    /// @param outputId The outputId of the output in the withdrawal transaction
    function withdraw(bytes32 txId, uint32 outputId) external payable {
        require(msg.value == depositAmount, "Invalid withdraw amount");
        UTXO memory utxo = UTXO({
            txId: txId,
            outputId: outputId
        });
        uint256 index = withdrawalUTXOs.length;
        withdrawalUTXOs.push(utxo);
        emit Withdrawal(utxo, index, block.timestamp);
    }
    
    /// @notice Batch version of `withdraw` that can accept multiple cBTC
    /// @dev Takes in multiple Bitcoin addresses as recipient addresses should be unique
    /// @param txIds the txIds of the withdrawal transactions on Bitcoin
    /// @param outputIds the outputIds of the outputs in the withdrawal transactions
    function batchWithdraw(bytes32[] calldata txIds, uint32[] calldata outputIds) external payable {
        require(txIds.length == outputIds.length, "Length mismatch");
        require(msg.value == depositAmount * txIds.length, "Invalid withdraw amount");
        uint256 index = withdrawalUTXOs.length;
        for (uint i = 0; i < txIds.length; i++) {
            UTXO memory utxo = UTXO({
                txId: txIds[i],
                outputId: outputIds[i]
            });
            withdrawalUTXOs.push(utxo);
            emit Withdrawal(utxo, index + i, block.timestamp);
        }
    }

    /// @return The count of withdrawals happened so far
    function getWithdrawalCount() external view returns (uint256) {
        return withdrawalUTXOs.length;
    }
    
    /// @notice Sets the operator address that can process user deposits
    /// @param _operator Address of the privileged operator
    function setOperator(address _operator) external onlyOwner {
        operator = _operator;
        emit OperatorUpdated(operator, _operator);
    }

    /// @notice Stores the filler of a certain withdrawal after the a user's withdrawal is covered on Bitcoin side
    /// @param withdrawTp Transaction parameters of the withdrawal transaction on Bitcoin
    /// @param inputIndex Index of the input that is the withdrawal UTXO (withdrawing user's ANYONECANPAY)
    /// @param withdrawId ID of the withdrawal action
    function declareWithdrawFiller(TransactionParams calldata withdrawTp, uint256 inputIndex, uint256 withdrawId) external {
        validateAndCheckInclusion(withdrawTp);
        bytes memory input = BTCUtils.extractInputAtIndex(withdrawTp.vin, inputIndex);
        bytes32 txId = BTCUtils.extractInputTxIdLE(input);
        uint32 index = uint32(BTCUtils.extractTxIndexLE(input));
        UTXO memory utxo = withdrawalUTXOs[withdrawId];
        require(utxo.txId == txId && utxo.outputId == index, "not matching UTXO");

        (, uint256 nOuts) = BTCUtils.parseVarInt(withdrawTp.vout);
        bytes memory _output = BTCUtils.extractOutputAtIndex(withdrawTp.vout, nOuts - 1);
        uint256 withdrawFillerId = uint256(bytesToBytes32(BTCUtils.extractOpReturnData(_output)));
        withdrawFillers[withdrawId] = getInternalOperatorId(withdrawFillerId);
        emit WithdrawFillerDeclared(withdrawId, withdrawFillerId);
    }

    // TODO: Add comment about using ValidateSPV for regular merkle proofs in natspec of this function
    function markMaliciousOperator(TransactionParams calldata kickoff2Tp) external {
        validateAndCheckInclusion(kickoff2Tp);
        
        (, uint256 _nOuts) = BTCUtils.parseVarInt(kickoff2Tp.vout);
        bytes memory _output = BTCUtils.extractOutputAtIndex(kickoff2Tp.vout, _nOuts - 1);
        uint256 _operatorId;
        bytes32 _moveTxId;
        (_operatorId, _moveTxId) = abi.decode(BTCUtils.extractOpReturnData(_output), (uint256, bytes32));
        uint256 _depositId = txIdToDepositId[_moveTxId];
        
        // TODO: look to the witness, check the NofN multisig

        bytes memory witness0 = WitnessUtils.extractWitnessAtIndex(kickoff2Tp.witness, 0);
        (, uint256 _nItems) = BTCUtils.parseVarInt(witness0);
        require(_nItems == 3, "Invalid witness items"); // musig + script + witness script

        bytes memory script = WitnessUtils.extractItemFromWitness(witness0, 1); // skip musig
        uint256 _len = kickoffScript.length;
        bytes memory _kickoffScript = script.slice(0, _len);
        require(isBytesEqual(_kickoffScript, kickoffScript), "Invalid kickoff script");

        if(withdrawFillers[_depositId] == 0 || withdrawFillers[_depositId] != getInternalOperatorId(_operatorId)) {
            isOperatorMalicious[_operatorId] = true;
        }

        emit MaliciousOperatorMarked(_operatorId);
    }

    function getInternalOperatorId(uint256 operatorId) internal pure returns (uint256) {
        return operatorId + 1;
    }

    // TODO: Consider not validating witness for non-deposit functions
    function validateAndCheckInclusion(TransactionParams calldata tp) internal view returns (bytes32, uint256) {
        bytes32 wtxId = WitnessUtils.calculateWtxId(tp.version, tp.flag, tp.vin, tp.vout, tp.witness, tp.locktime);
        require(BTCUtils.validateVin(tp.vin), "Vin is not properly formatted");
        require(BTCUtils.validateVout(tp.vout), "Vout is not properly formatted");
        
        (, uint256 _nIns) = BTCUtils.parseVarInt(tp.vin);
        // Number of inputs == number of witnesses
        require(WitnessUtils.validateWitness(tp.witness, _nIns), "Witness is not properly formatted");

        require(LIGHT_CLIENT.verifyInclusion(tp.block_height, wtxId, tp.intermediate_nodes, tp.index), "Transaction is not in block");

        return (wtxId, _nIns);
    }

    function extractRecipientAddress(bytes memory _script) internal view returns (address) {
        uint256 offset = depositScript.length;
        bytes20 _addr = bytes20(_script.slice(offset, 20));
        return address(uint160(_addr));
    }

    /// @notice Checks if two byte sequences are equal in chunks of 32 bytes
    /// @dev This approach compares chunks of 32 bytes using bytes32 equality checks for optimization
    /// @param a First byte sequence
    /// @param b Second byte sequence
    function isBytesEqual(bytes memory a, bytes memory b) internal pure returns (bool result) {
        uint256 len = a.length;
        if (len != b.length) {
            return false;
        }

        uint256 offset = 32;
        bytes32 chunkA;
        bytes32 chunkB;
        while (offset <= len) {
            assembly {
                chunkA := mload(add(a, offset)) 
                chunkB := mload(add(b, offset))
                offset := add(offset, 32)
            }
            if (chunkA != chunkB) {
                return false;
            }
        }

        // Check remaining bytes (if any)
        for (uint i = offset - 32; i < len; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }

        return true;
    }

    function bytesToBytes32(bytes memory source) internal pure returns (bytes32 result) {
        return abi.decode(source, (bytes32));
    }
}
