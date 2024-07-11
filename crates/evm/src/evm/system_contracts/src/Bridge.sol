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

    struct DepositParams {
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

    BitcoinLightClient public constant LIGHT_CLIENT = BitcoinLightClient(address(0x3100000000000000000000000000000000000001));
    address public constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);

    bool public initialized;
    uint256 public constant DEPOSIT_AMOUNT = 0.01 ether;
    address public operator;
    uint256 public requiredSigsCount;
    bytes public depositScript;
    bytes public scriptSuffix;
    
    mapping(bytes32 => bool) public spentWtxIds;
    bytes32[] public withdrawalAddrs;
    
    event Deposit(bytes32 wtxId, address recipient, uint256 timestamp);
    event Withdrawal(bytes32 bitcoin_address, uint256 index, uint256 timestamp);
    event DepositScriptUpdate(bytes depositScript, bytes scriptSuffix, uint256 requiredSigsCount);
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
    /// @param _depositScript The deposit script expected in the witness field for all L1 deposits
    /// @param _scriptSuffix The suffix of the deposit script that follows the receiver address
    /// @param _requiredSigsCount The number of signatures that is contained in the deposit script
    function initialize(bytes calldata _depositScript, bytes calldata _scriptSuffix, uint256 _requiredSigsCount) external onlySystem {
        require(!initialized, "Contract is already initialized");
        require(_requiredSigsCount != 0, "Verifier count cannot be 0");
        require(_depositScript.length != 0, "Deposit script cannot be empty");

        initialized = true;
        depositScript = _depositScript;
        scriptSuffix = _scriptSuffix;
        requiredSigsCount = _requiredSigsCount;
        
        // Set initial operator to SYSTEM_CALLER so that Citrea can get operational by starting to process deposits
        operator = SYSTEM_CALLER;

        emit OperatorUpdated(address(0), SYSTEM_CALLER);
        emit DepositScriptUpdate(_depositScript, _scriptSuffix, _requiredSigsCount);
    }

    /// @notice Sets the expected deposit script of the deposit transaction on Bitcoin, contained in the witness
    /// @dev Deposit script contains a fixed script that checks signatures of verifiers and pushes EVM address of the receiver
    /// @param _depositScript The new deposit script
    /// @param _scriptSuffix The part of the deposit script that succeeds the receiver address
    /// @param _requiredSigsCount The number of signatures that are needed for deposit transaction
    function setDepositScript(bytes calldata _depositScript, bytes calldata _scriptSuffix, uint256 _requiredSigsCount) external onlyOwner {
        require(_requiredSigsCount != 0, "Verifier count cannot be 0");
        require(_depositScript.length != 0, "Deposit script cannot be empty");

        depositScript = _depositScript;
        scriptSuffix = _scriptSuffix;
        requiredSigsCount = _requiredSigsCount;

        emit DepositScriptUpdate(_depositScript, _scriptSuffix, _requiredSigsCount);
    }

    /// @notice Checks if the deposit amount is sent to the bridge multisig on Bitcoin, and if so, sends the deposit amount to the receiver
    /// @param p The deposit parameters that contains the info of the deposit transaction on Bitcoin
    function deposit(
        DepositParams calldata p
    ) external onlyOperator {
        // We don't need to check if the contract is initialized, as without an `initialize` call and `deposit` calls afterwards,
        // only the system caller can execute a transaction on Citrea, as no addresses have any balance. Thus there's no risk of 
        // `deposit` being called before `initialize` maliciously.
        
        bytes32 wtxId = WitnessUtils.calculateWtxId(p.version, p.flag, p.vin, p.vout, p.witness, p.locktime);
        require(!spentWtxIds[wtxId], "wtxId already spent");
        spentWtxIds[wtxId] = true;

        require(BTCUtils.validateVin(p.vin), "Vin is not properly formatted");
        require(BTCUtils.validateVout(p.vout), "Vout is not properly formatted");
        
        (, uint256 _nIns) = BTCUtils.parseVarInt(p.vin);
        require(_nIns == 1, "Only one input allowed");
        // Number of inputs == number of witnesses
        require(WitnessUtils.validateWitness(p.witness, _nIns), "Witness is not properly formatted");

        require(LIGHT_CLIENT.verifyInclusion(p.block_height, wtxId, p.intermediate_nodes, p.index), "Transaction is not in block");

        bytes memory witness0 = WitnessUtils.extractWitnessAtIndex(p.witness, 0);
        (, uint256 _nItems) = BTCUtils.parseVarInt(witness0);
        require(_nItems == requiredSigsCount + 2, "Invalid witness items"); // verifier sigs + deposit script + witness script

        bytes memory script = WitnessUtils.extractItemFromWitness(witness0, requiredSigsCount);
        uint256 _len = depositScript.length;
        bytes memory _depositScript = script.slice(0, _len);
        require(isBytesEqual(_depositScript, depositScript), "Invalid deposit script");
        bytes memory _suffix = script.slice(_len + 20, script.length - (_len + 20)); // 20 bytes for address
        require(isBytesEqual(_suffix, scriptSuffix), "Invalid script suffix");

        address recipient = extractRecipientAddress(script);

        emit Deposit(wtxId, recipient, block.timestamp);

        (bool success, ) = recipient.call{value: DEPOSIT_AMOUNT}("");
        require(success, "Transfer failed");
    }

    /// @notice Accepts 1 cBTC from the sender and inserts this withdrawal request of 1 BTC on Bitcoin into the withdrawals array so that later on can be processed by the operator 
    /// @param bitcoin_address The Bitcoin address of the receiver
    function withdraw(bytes32 bitcoin_address) external payable {
        require(msg.value == DEPOSIT_AMOUNT, "Invalid withdraw amount");
        uint256 index = withdrawalAddrs.length;
        withdrawalAddrs.push(bitcoin_address);
        emit Withdrawal(bitcoin_address, index, block.timestamp);
    }
    
    /// @notice Batch version of `withdraw` that can accept multiple cBTC
    /// @dev Takes in multiple Bitcoin addresses as recipient addresses should be unique
    /// @param bitcoin_addresses The Bitcoin addresses of the receivers
    function batchWithdraw(bytes32[] calldata bitcoin_addresses) external payable {
        require(msg.value == DEPOSIT_AMOUNT * bitcoin_addresses.length, "Invalid withdraw amount");
        uint256 index = withdrawalAddrs.length;
        for (uint i = 0; i < bitcoin_addresses.length; i++) {
            withdrawalAddrs.push(bitcoin_addresses[i]);
            emit Withdrawal(bitcoin_addresses[i], index + i, block.timestamp);
        }
    }

    /// @return The count of withdrawals happened so far
    function getWithdrawalCount() external view returns (uint256) {
        return withdrawalAddrs.length;
    }
    
    /// @notice Sets the operator address that can process user deposits
    /// @param _operator Address of the privileged operator
    function setOperator(address _operator) external onlyOwner {
        operator = _operator;
        emit OperatorUpdated(operator, _operator);
    }
    
    /// @notice Checks if two byte sequences are equal
    /// @dev This is not efficient, and a better approach would be doing a hash based comparison but as this is ran in a zkEVM, hashing is inefficient
    /// @param a First byte sequence
    /// @param b Second byte sequence
    function isBytesEqual(bytes memory a, bytes memory b) internal pure returns (bool result) {
        require(a.length == b.length, "Lengths do not match");

        // Cannot use keccak as its costly in ZK environment
        uint length = a.length;
        for (uint i = 0; i < length; i++) {
            if (a[i] != b[i]) {
                result = false;
                return result;
            }
        }
        result = true;
    }

    function extractRecipientAddress(bytes memory _script) internal view returns (address) {
        uint256 offset = depositScript.length;
        bytes20 _addr = bytes20(_script.slice(offset, 20));
        return address(uint160(_addr));
    }
}
