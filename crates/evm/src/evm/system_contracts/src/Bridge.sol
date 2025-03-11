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
        bytes4 outputId;
    }

    BitcoinLightClient public constant LIGHT_CLIENT = BitcoinLightClient(address(0x3100000000000000000000000000000000000001));
    address public constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);

    bool public initialized;
    address public operator;
    uint256 public depositAmount;
    uint256 currentDepositId;
    bytes public scriptPrefix;
    bytes public scriptSuffix;

    UTXO[] public withdrawalUTXOs;
    bytes32[] public depositTxIds;

    mapping(bytes32 => uint256) public txIdToDepositId;
    
    event Deposit(bytes32 wtxId, bytes32 txId, address recipient, uint256 timestamp, uint256 depositId);
    event Withdrawal(UTXO utxo, uint256 index, uint256 timestamp);
    event DepositScriptUpdate(bytes scriptPrefix, bytes scriptSuffix);
    event OperatorUpdated(address oldOperator, address newOperator);

    modifier onlySystem() {
        require(msg.sender == SYSTEM_CALLER, "caller is not the system caller");
        _;
    }

    modifier onlyOperator() {
        require(msg.sender == operator, "caller is not the operator");
        _;
    }

    /// @notice Initializes the bridge contract and sets the deposit script
    /// @param _scriptPrefix First part of the deposit script expected in the witness field for all L1 deposits 
    /// @param _scriptSuffix The suffix of the deposit script that follows the receiver address
    /// @param _depositAmount The CBTC amount that can be deposited and withdrawn
    function initialize(bytes calldata _scriptPrefix, bytes calldata _scriptSuffix, uint256 _depositAmount) external onlySystem {
        require(!initialized, "Contract is already initialized");
        require(_depositAmount != 0, "Deposit amount cannot be 0");
        require(_scriptPrefix.length != 0, "Deposit script cannot be empty");

        initialized = true;
        scriptPrefix = _scriptPrefix;
        scriptSuffix = _scriptSuffix;
        depositAmount = _depositAmount;
        
        // Set initial operator to SYSTEM_CALLER so that Citrea can get operational by starting to process deposits
        operator = SYSTEM_CALLER;

        // Add a dummy UTXO to the withdrawalUTXOs array to avoid index 0 being used
        withdrawalUTXOs.push(UTXO({txId: bytes32(0), outputId: bytes4(0)}));
        // Add a dummy txId to the depositTxIds array to avoid index 0 being used
        depositTxIds.push(bytes32(0));

        emit OperatorUpdated(address(0), SYSTEM_CALLER);
        emit DepositScriptUpdate(_scriptPrefix, _scriptSuffix);
    }

    /// @notice Sets the expected deposit script of the deposit transaction on Bitcoin, contained in the witness
    /// @dev Deposit script contains a fixed script that checks signatures of verifiers and pushes EVM address of the receiver
    /// @param _scriptPrefix The new deposit script prefix
    /// @param _scriptSuffix The part of the deposit script that succeeds the receiver address
    function setDepositScript(bytes calldata _scriptPrefix, bytes calldata _scriptSuffix) external onlyOwner {
        require(_scriptPrefix.length != 0, "Deposit script cannot be empty");

        scriptPrefix = _scriptPrefix;
        scriptSuffix = _scriptSuffix;

        emit DepositScriptUpdate(_scriptPrefix, _scriptSuffix);
    }

    /// @notice Checks if the deposit amount is sent to the bridge multisig on Bitcoin, and if so, sends the deposit amount to the receiver
    /// @param moveTp Transaction parameters of the move transaction on Bitcoin
    function deposit(
        TransactionParams calldata moveTp 
    ) external onlyOperator {
        // We don't need to check if the contract is initialized, as without an `initialize` call and `deposit` calls afterwards,
        // only the system caller can execute a transaction on Citrea, as no addresses have any balance. Thus there's no risk of 
        // `deposit` being called before `initialize` maliciously.
        
        (bytes32 wtxId, uint256 nIns) = validateAndCheckInclusion(moveTp);
        require(nIns == 1, "Only one input allowed");
        bytes32 txId = ValidateSPV.calculateTxId(moveTp.version, moveTp.vin, moveTp.vout, moveTp.locktime);

        require(txIdToDepositId[txId] == 0, "txId already spent");
        txIdToDepositId[txId] = ++currentDepositId;
        depositTxIds.push(txId);
        
        bytes memory witness0 = WitnessUtils.extractWitnessAtIndex(moveTp.witness, 0);
        (, uint256 nItems) = BTCUtils.parseVarInt(witness0);
        require(nItems == 3, "Invalid witness items"); // musig + script + witness script

        bytes memory script = WitnessUtils.extractItemFromWitness(witness0, 1); // skip musig
        uint256 len = scriptPrefix.length;
        bytes memory _scriptPrefix = script.slice(0, len);
        require(isBytesEqual(_scriptPrefix, scriptPrefix), "Invalid deposit script");
        bytes memory _scriptSuffix = script.slice(script.length - scriptSuffix.length, scriptSuffix.length);
        require(isBytesEqual(_scriptSuffix, scriptSuffix), "Invalid script suffix");

        address recipient = extractRecipientAddress(script);
        emit Deposit(wtxId, txId, recipient, block.timestamp, currentDepositId);

        (bool success, ) = recipient.call{value: depositAmount}("");
        require(success, "Transfer failed");
    }

    /// @notice Accepts 1 cBTC from the sender and inserts this withdrawal request of 1 BTC on Bitcoin into the withdrawals array so that later on can be processed by the operator 
    /// @param txId The txId of the withdrawal transaction on Bitcoin
    /// @param outputId The outputId of the output in the withdrawal transaction
    function withdraw(bytes32 txId, bytes4 outputId) external payable {
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
    function batchWithdraw(bytes32[] calldata txIds, bytes4[] calldata outputIds) external payable {
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

    function validateAndCheckInclusion(TransactionParams calldata tp) internal view returns (bytes32, uint256) {
        bytes32 wtxId = WitnessUtils.calculateWtxId(tp.version, tp.flag, tp.vin, tp.vout, tp.witness, tp.locktime);
        require(BTCUtils.validateVin(tp.vin), "Vin is not properly formatted");
        require(BTCUtils.validateVout(tp.vout), "Vout is not properly formatted");
        
        (, uint256 nIns) = BTCUtils.parseVarInt(tp.vin);
        // Number of inputs == number of witnesses
        require(WitnessUtils.validateWitness(tp.witness, nIns), "Witness is not properly formatted");

        require(LIGHT_CLIENT.verifyInclusion(tp.block_height, wtxId, tp.intermediate_nodes, tp.index), "Transaction is not in block");

        return (wtxId, nIns);
    }

    function extractRecipientAddress(bytes memory _script) internal view returns (address) {
        uint256 offset = scriptPrefix.length;
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

    function bytesToBytes32(bytes memory _source) pure internal returns (bytes32 result) {
        if (_source.length == 0) {
            return 0x0;
        }
        uint256 length = _source.length;
        require(length <= 32, "Bytes cannot be more than 32 bytes");
        uint256 diff;
        assembly {
            result := mload(add(_source, 32))
            diff := sub(32, length)
            result := shr(mul(diff, 8), result)
        }
    }
}