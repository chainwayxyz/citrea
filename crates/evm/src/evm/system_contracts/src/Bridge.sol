// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import "bitcoin-spv/solidity/contracts/ValidateSPV.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";
import "../lib/WitnessUtils.sol";
import "./BitcoinLightClient.sol";
import "openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";

/// @title Bridge contract for the Citrea end of Citrea <> Bitcoin bridge
/// @author Citrea

/// @dev This contract is not intended for regular deployment and can only be used as a predeploy.
/// @dev It does not utilize OpenZeppelin's initialization chain, thus any modifications that include new OZ logic should be made carefully.

contract Bridge is Ownable2StepUpgradeable, PausableUpgradeable {
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

    struct MerkleProof {
        bytes intermediateNodes;
        uint256 blockHeight;
        uint256 index;
    }

    struct UTXO {
        bytes32 txId;
        bytes4 outputId;
    }

    BitcoinLightClient public constant LIGHT_CLIENT = BitcoinLightClient(address(0x3100000000000000000000000000000000000001));
    address public constant SYSTEM_CALLER = address(0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD);
    address public constant SCHNORR_VERIFIER_PRECOMPILE = address(0x200);
    uint256 public constant SAT_TO_WEI = 10**10;
    uint256 public constant PAYOUT_ANCHOR_OUTPUT_AMOUNT = 240;

    bytes public constant EPOCH = hex"00";
    bytes public constant SIGHASH_DEFAULT_HASH_TYPE = hex"00";
    bytes public constant SIGHASH_SINGLE_ANYONECANPAY_HASH_TYPE = hex"83";
    bytes public constant SPEND_TYPE_NO_EXT = hex"00";
    bytes public constant SPEND_TYPE_EXT = hex"02";
    bytes public constant INPUT_INDEX = hex"00000000";
    bytes public constant KEY_VERSION = hex"00";
    bytes public constant CODESEP_POS = hex"ffffffff";

    bool public initialized;
    address public operator;
    uint256 public depositAmount;
    address public failedDepositVault;
    bytes public depositPrefix;
    bytes public depositSuffix;
    bytes public replacePrefix;
    bytes public replaceSuffix;

    UTXO[] public withdrawalUTXOs;
    bytes32[] public depositTxIds;

    mapping(bytes32 => bool) public processedTxIds;
    mapping(bytes32 => bool) public usedWithdrawalUTXO;

    uint256 public optimisticWithdrawAmountSats;
    
    event Deposit(bytes32 wtxId, bytes32 txId, address recipient, uint256 timestamp, uint256 depositId);
    event Withdrawal(UTXO utxo, uint256 index, uint256 timestamp);
    event SafeWithdrawal(Transaction payoutTx, UTXO spentUtxo, uint256 index);
    event DepositScriptUpdate(bytes depositPrefix, bytes depositSuffix);
    event ReplaceScriptUpdate(bytes replacePrefix, bytes replaceSuffix);
    event DepositReplaced(uint256 index, bytes32 oldTxId, bytes32 newTxId);
    event OperatorUpdated(address oldOperator, address newOperator);
    event FailedDepositVaultUpdated(address oldVault, address newVault);
    event DepositTransferFailed(bytes32 wtxId, bytes32 txId, address recipient, uint256 timestamp, uint256 depositId);
    event OptimisticWithdrawAmountSet(uint256 amount);

    modifier onlySystem() {
        require(msg.sender == SYSTEM_CALLER, "caller is not the system caller");
        _;
    }

    modifier onlyOperator() {
        require(msg.sender == operator, "caller is not the operator");
        _;
    }

    modifier onlySystemOrOperator() {
        require(msg.sender == SYSTEM_CALLER || msg.sender == operator, "caller is not the system caller or operator");
        _;
    }

    modifier onlyOwnerOrOperator() {
        require(msg.sender == owner() || msg.sender == operator, "caller is not the owner or operator");
        _;
    }

    /// @notice Initializes the bridge contract and sets the deposit script
    /// @dev This function does not utilize OZ's initialization chain and instead uses a state variable to track initialization status
    /// @param _depositPrefix First part of the deposit script expected in the witness field for all L1 deposits 
    /// @param _depositSuffix The suffix of the deposit script that follows the receiver address
    /// @param _depositAmount The CBTC amount that can be deposited and withdrawn
    function initialize(bytes calldata _depositPrefix, bytes calldata _depositSuffix, uint256 _depositAmount) external onlySystem {
        require(!initialized, "Contract is already initialized");
        require(_depositAmount != 0, "Deposit amount cannot be 0");
        require(_depositPrefix.length >= 34, "Deposit script must be longer than 34 bytes");
        require(_depositAmount % SAT_TO_WEI == 0, "Deposit amount must have valid satoshi value");
        require(_depositAmount / SAT_TO_WEI <= type(uint64).max, "Deposit amount divided by SAT_TO_WEI must fit in uint64");

        initialized = true;
        depositPrefix = _depositPrefix;
        depositSuffix = _depositSuffix;
        depositAmount = _depositAmount;
        // Set initial optimistic withdraw amount to deposit amount minus `payoutTx`'s anchor output amount
        uint256 _optimisticWithdrawAmountSats = (_depositAmount / SAT_TO_WEI) - PAYOUT_ANCHOR_OUTPUT_AMOUNT;
        optimisticWithdrawAmountSats = _optimisticWithdrawAmountSats;

        // Set initial operator to SYSTEM_CALLER
        operator = SYSTEM_CALLER;
        // Set initial failed deposit vault to pre-deployed vault
        failedDepositVault = address(0x3100000000000000000000000000000000000007);
        
        emit OperatorUpdated(address(0), SYSTEM_CALLER);
        emit DepositScriptUpdate(_depositPrefix, _depositSuffix);
        emit FailedDepositVaultUpdated(address(0), address(0x3100000000000000000000000000000000000007));
        emit OptimisticWithdrawAmountSet(_optimisticWithdrawAmountSats);
    }

    /// @notice Sets the expected deposit script of the deposit transaction on Bitcoin, contained in the witness
    /// @dev Deposit script contains a fixed script that checks signatures of verifiers and pushes EVM address of the receiver
    /// @param _depositPrefix The new deposit script prefix
    /// @param _depositSuffix The part of the deposit script that succeeds the receiver address
    function setDepositScript(bytes calldata _depositPrefix, bytes calldata _depositSuffix) external onlyOwner {
        require(_depositPrefix.length >= 34, "Deposit script must be longer than 34 bytes");

        depositPrefix = _depositPrefix;
        depositSuffix = _depositSuffix;

        emit DepositScriptUpdate(_depositPrefix, _depositSuffix);
    }

    /// @notice Sets the replace script of the replacement transaction on Bitcoin, contained in the witness
    /// @dev Replace script contains a fixed script that checks signatures of verifiers and pushes txId of the deposit transaction to be replaced
    /// @param _replacePrefix The new replace prefix
    /// @param _replaceSuffix The part of the replace script that succeeds the txId
    function setReplaceScript(bytes calldata _replacePrefix, bytes calldata _replaceSuffix) external onlyOwner {
        require(_replacePrefix.length >= 34, "Replace script must be longer than 34 bytes");
        require(bytesToBytes32(_replacePrefix.slice(2, 32)) == bytesToBytes32(getAggregatedKey()), "Replace prefix must contain the same aggregated key as deposit prefix");

        replacePrefix = _replacePrefix;
        replaceSuffix = _replaceSuffix;

        emit ReplaceScriptUpdate(_replacePrefix, _replaceSuffix);
    }

    /// @notice Sets the address of the failed deposit vault
    /// @param _failedDepositVault The address of the failed deposit vault
    function setFailedDepositVault(address _failedDepositVault) external onlyOwner {
        require(_failedDepositVault != address(0), "Invalid address");
        address oldVault = failedDepositVault;
        failedDepositVault = _failedDepositVault;
        emit FailedDepositVaultUpdated(oldVault, _failedDepositVault);
    }

    /// @notice Sets the expected withdraw amount in the output of `payoutTx` in `safeWithdraw`
    /// @notice This is the BTC amount user actually receives on Bitcoin when they withdraw
    /// @param _optimisticWithdrawAmountSats The new optimistic withdraw amount in satoshis
    function setOptimisticWithdrawAmountSats(uint256 _optimisticWithdrawAmountSats) external onlyOwner {
        require(_optimisticWithdrawAmountSats != 0, "Optimistic withdraw amount cannot be 0");
        optimisticWithdrawAmountSats = _optimisticWithdrawAmountSats;
        emit OptimisticWithdrawAmountSet(_optimisticWithdrawAmountSats);
    }

    /// @notice Checks if the deposit amount is sent to the bridge multisig on Bitcoin, and if so, sends the deposit amount to the receiver
    /// @param moveTx Transaction parameters of the move transaction on Bitcoin
    /// @param proof Merkle proof of the move transaction
    /// @param shaScriptPubkeys `shaScriptPubkeys` is the only component of the P2TR message hash that cannot be derived solely on the transaction itself in our case,
    /// as it requires knowledge of the previous transaction output that is being spent. Thus we calculate this component off-chain.
    function deposit(
        Transaction calldata moveTx,
        MerkleProof calldata proof,
        bytes32 shaScriptPubkeys
    ) external onlySystemOrOperator whenNotPaused {
        // We don't need to check if the contract is initialized, as without an `initialize` call and `deposit` calls afterwards,
        // only the system caller can execute a transaction on Citrea, as no addresses have any balance. Thus there's no risk of 
        // `deposit` being called before `initialize` maliciously.

        // Validate that the move transaction is properly formatted and is included in a Bitcoin block
        (bytes32 wtxId, uint256 nIns) = validateAndCheckInclusion(moveTx, proof);
        require(nIns == 1, "Only one input allowed");

        // In order to verify the P2TR signature, we need to reconstruct the message hash and that is derived from input, output and the corresponding witness field
        bytes memory input = moveTx.vin.extractInputAtIndex(0);
        // Since `moveTx` is guaranteed to have <= 252 outputs, we can safely assume the compact size to be single byte and skip one byte
        // `moveTx` is constructed by Clementine so it is also safe to assume minimal encoding of the compact size
        bytes memory outputs = moveTx.vout.slice(1, moveTx.vout.length - 1);
        bytes memory witness0 = WitnessUtils.extractWitnessAtIndex(moveTx.witness, 0);

        // Verify the P2TR Schnorr signature from n-of-n which is included in move transaction
        verifySigInTx(input, outputs, witness0, moveTx.version, moveTx.locktime, shaScriptPubkeys);

        // Nullify the move transaction based on txId
        bytes32 txId = ValidateSPV.calculateTxId(moveTx.version, moveTx.vin, moveTx.vout, moveTx.locktime);
        require(!processedTxIds[txId], "txId already spent");
        processedTxIds[txId] = true;
        depositTxIds.push(txId);
        
        // Our P2TR script path spend unlocking witness should have exactly 3 witness items
        (, uint256 nItems) = BTCUtils.parseVarInt(witness0);
        require(nItems == 3, "Invalid witness items"); // musig signature + script + witness script

        bytes memory script = WitnessUtils.extractItemFromWitness(witness0, 1); // skip musig signature
        // Unlocking witness script is consisted of a fixed prefix and suffix part with a variable receiver address in between
        uint256 prefixLen = depositPrefix.length;
        uint256 suffixLen = depositSuffix.length;
        // Assert if the parsed script is of the correct length, and that it starts with the prefix and ends with the suffix
        require(script.length == prefixLen + 20 + suffixLen, "Invalid script length");
        bytes memory _depositPrefix = script.slice(0, prefixLen);
        require(isBytesEqual(_depositPrefix, depositPrefix), "Invalid deposit script");
        bytes memory _depositSuffix = script.slice(script.length - suffixLen, suffixLen);
        require(isBytesEqual(_depositSuffix, depositSuffix), "Invalid script suffix");

        address recipient = extractRecipientAddress(script);

        (bool success, ) = recipient.call{value: depositAmount}("");
        if(!success) {
            // If the transfer fails, we send the funds to the failed deposit vault
            emit DepositTransferFailed(wtxId, txId, recipient, block.timestamp, depositTxIds.length - 1);
            (success, ) = failedDepositVault.call{value: depositAmount}("");
            require(success, "Failed to send to failed deposit vault");
        } else {
            emit Deposit(wtxId, txId, recipient, block.timestamp, depositTxIds.length - 1);
        }
    }

    /// @notice Accepts `depositAmount` cBTC from the sender and inserts this withdrawal request of `depositAmount` BTC on Bitcoin into the withdrawals array so that later on can be processed by the operator 
    /// @param txId The txId of the withdrawal transaction on Bitcoin
    /// @param outputId The outputId of the output in the withdrawal transaction
    function withdraw(bytes32 txId, bytes4 outputId) public payable whenNotPaused {
        require(msg.value == depositAmount, "Invalid withdraw amount");

        bytes32 utxoKey = sha256(abi.encodePacked(txId, outputId));
        require(!usedWithdrawalUTXO[utxoKey], "UTXO already used");
        usedWithdrawalUTXO[utxoKey] = true;

        UTXO memory utxo = UTXO({
            txId: txId,
            outputId: outputId
        });
        uint256 index = withdrawalUTXOs.length;
        withdrawalUTXOs.push(utxo);
        emit Withdrawal(utxo, index, block.timestamp);
    }

    /// @notice Same operation as `withdraw` with extra validations at the cost of gas. Validates the transactions, checks the inclusion of the transaction being spent and checks if the signature is valid.
    /// @param prepareTx Transaction parameters of the prepare transaction on Bitcoin
    /// @param prepareProof Merkle proof of the prepare transaction
    /// @param payoutTx Transaction parameters of the payout transaction on Bitcoin
    /// @param blockHeader Block header of the associated Bitcoin block
    /// @param withdrawalAddressPubKey The script pubkey of the user that BTC is withdrawn to, included for extra validation
    function safeWithdraw(Transaction calldata prepareTx, MerkleProof calldata prepareProof, Transaction calldata payoutTx, bytes calldata blockHeader, bytes memory withdrawalAddressPubKey) external payable {
        // Validate format and inclusion of the prepare transaction
        require(BTCUtils.validateVin(prepareTx.vin), "Vin is not properly formatted");
        require(BTCUtils.validateVout(prepareTx.vout), "Vout is not properly formatted");
        bytes32 txId = ValidateSPV.calculateTxId(prepareTx.version, prepareTx.vin, prepareTx.vout, prepareTx.locktime);
        require(LIGHT_CLIENT.verifyInclusionByTxId(prepareProof.blockHeight, txId, blockHeader, prepareProof.intermediateNodes, prepareProof.index), "Transaction is not in block");

        // Validate format of payout transaction, as this transaction is not mined in this format (it's a PSBT meaning that additional inputs will be added later) its inclusion cannot be checked
        require(BTCUtils.validateVin(payoutTx.vin), "Payout vin is not properly formatted");
        (, uint256 nIns) = BTCUtils.parseVarInt(payoutTx.vin);
        (, uint256 nOuts) = BTCUtils.parseVarInt(payoutTx.vout);
        require(nIns == 1, "Payout vin should have exactly one input");
        require(nOuts == 1, "Payout vout should have exactly one output");
        require(BTCUtils.validateVout(payoutTx.vout), "Payout vout is not properly formatted");
        require(WitnessUtils.validateWitness(payoutTx.witness, 1), "Payout witness is not properly formatted");
        
        bytes memory payoutInput = payoutTx.vin.extractInputAtIndex(0);
        bytes memory payoutOutput = payoutTx.vout.extractOutputAtIndex(0);
        bytes memory payoutWitness = WitnessUtils.extractWitnessAtIndex(payoutTx.witness, 0);

        // Assert that the payout output value is the expected optimistic withdraw amount
        require(uint256(payoutOutput.extractValue()) == optimisticWithdrawAmountSats, "Payout output value does not match optimistic withdraw amount");

        // Assert the user provided script pubkey is the same as the one in the payout transaction's output
        (uint256 varIntDataLen, uint256 pubKeyLen) = BTCUtils.parseVarIntAt(payoutOutput, 8);
        require(isBytesEqual(payoutOutput.slice(9 + varIntDataLen, pubKeyLen), withdrawalAddressPubKey), "Invalid payout output script pubkey");

        // Payout tx should spend the prepare tx, so we need to check if the txId of the input matches the txId of the prepare transaction
        bytes32 spentTxId = payoutInput.extractInputTxIdLE();
        require(spentTxId == txId, "Invalid spent txId");

        // Assert that the spent output is a P2TR output and that the script pubkey is the same as the one provided in parameters
        bytes4 spentIndex = payoutInput.extractTxIndexLE();
        bytes memory spentOutput = prepareTx.vout.extractOutputAtIndex(BTCUtils.reverseUint32(uint32(spentIndex)));
        require(spentOutput.length == 43, "Invalid spent output length"); // 8 bytes for amount + 1 byte for script pub key length + 2 bytes for OP_1 OP_PUSHBYTES32 + 32 bytes for the hash
        require(isBytesEqual(spentOutput.slice(8, 1), hex"22"), "Invalid spent output script pubkey length");
        require(isBytesEqual(spentOutput.slice(9, 2), hex"5120"), "Spent output is not a P2TR output"); // OP_1 OP_PUSHBYTES32
        bytes memory pubKey = spentOutput.slice(11, 32);
        bytes4 sequence = payoutInput.extractSequenceLEWitness();
        bytes32 shaSingleOutput = sha256(abi.encodePacked(payoutOutput));

        // Construct the message hash for the P2TR signature according to BIP-341
        bytes memory message = abi.encodePacked(EPOCH, SIGHASH_SINGLE_ANYONECANPAY_HASH_TYPE, payoutTx.version, payoutTx.locktime, SPEND_TYPE_NO_EXT, spentTxId, spentIndex, spentOutput, sequence, shaSingleOutput);
        bytes32 messageHash = taggedHash("TapSighash", message);
        bytes memory signatureWithLen = payoutWitness.extractItemFromWitness(0);
        bytes memory signature = signatureWithLen.slice(1, signatureWithLen.length - 1);
        
        require(isSchnorrSigValid(pubKey, messageHash, signature), "Invalid signature");
        
        UTXO memory spentUtxo = UTXO({
            txId: spentTxId,
            outputId: spentIndex
        });
        emit SafeWithdrawal(payoutTx, spentUtxo, withdrawalUTXOs.length);

        withdraw(spentTxId, spentIndex);
    }
    
    /// @notice Batch version of `withdraw` that can accept multiple cBTC
    /// @dev Takes in multiple Bitcoin addresses as recipient addresses should be unique
    /// @param txIds the txIds of the withdrawal transactions on Bitcoin
    /// @param outputIds the outputIds of the outputs in the withdrawal transactions
    function batchWithdraw(bytes32[] calldata txIds, bytes4[] calldata outputIds) external payable whenNotPaused {
        require(txIds.length == outputIds.length, "Length mismatch");
        require(msg.value == depositAmount * txIds.length, "Invalid withdraw amount");
        uint256 index = withdrawalUTXOs.length;
        for (uint256 i = 0; i < txIds.length; i++) {
            bytes32 utxoKey = sha256(abi.encodePacked(txIds[i], outputIds[i]));
            require(!usedWithdrawalUTXO[utxoKey], "UTXO already used");
            usedWithdrawalUTXO[utxoKey] = true;

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
        require(_operator != address(0), "Operator cannot be zero address");
        address oldOperator = operator;
        operator = _operator;
        emit OperatorUpdated(oldOperator, _operator);
    }

    /// @notice Operator can replace a deposit transaction with its replacement if the replacement transaction is included in Bitcoin and signed by N-of-N with the replacement script
    /// @param replaceTx Transaction parameters of the replacement transaction on Bitcoin
    /// @param proof Merkle proof of the replacement transaction
    /// @param idToReplace The index of the deposit transaction to be replaced in the `depositTxIds` array
    /// @param shaScriptPubkeys `shaScriptPubkeys` is the only component of the P2TR message hash that cannot be derived solely on the transaction itself in our case,
    /// as it requires knowledge of the previous transaction output that is being spent. Thus we calculate this component off-chain.
    function replaceDeposit(Transaction calldata replaceTx, MerkleProof calldata proof, uint256 idToReplace, bytes32 shaScriptPubkeys) external onlyOperator {
        require(idToReplace < depositTxIds.length, "Invalid index");
        require(replacePrefix.length != 0, "Replace script is not set");
        
        // Validate that the replace transaction is properly formatted and is included in a Bitcoin block
        (, uint256 nIns) = validateAndCheckInclusion(replaceTx, proof);
        require(nIns == 1, "Only one input allowed");

        // In order to verify the P2TR signature, we need to reconstruct the message hash and that is derived from input, output and the corresponding witness field
        bytes memory input = replaceTx.vin.extractInputAtIndex(0);
        // Since `replaceTx` is guaranteed to have <= 252 outputs, we can safely assume the compact size to be single byte and skip one byte
        // `replaceTx` is constructed by Clementine so it is also safe to assume minimal encoding of the compact size
        bytes memory outputs = replaceTx.vout.slice(1, replaceTx.vout.length - 1);
        bytes memory witness0 = WitnessUtils.extractWitnessAtIndex(replaceTx.witness, 0);

        // Verify the P2TR Schnorr signature from n-of-n which is included in replace transaction
        verifySigInTx(input, outputs, witness0, replaceTx.version, replaceTx.locktime, shaScriptPubkeys);

        // Nullify the replace transaction based on txId
        bytes32 newTxId = ValidateSPV.calculateTxId(replaceTx.version, replaceTx.vin, replaceTx.vout, replaceTx.locktime);
        require(!processedTxIds[newTxId], "txId already used to replace");
        processedTxIds[newTxId] = true;

        // Cache the existing txId to be replaced before overwriting it
        bytes32 txIdToReplace = depositTxIds[idToReplace];
        depositTxIds[idToReplace] = newTxId;

        (, uint256 nItems) = BTCUtils.parseVarInt(witness0);
        // Our P2TR script path spend unlocking witness should have exactly 3 witness items
        require(nItems == 3, "Invalid witness items"); // musig signature + script + witness script
        bytes memory script = WitnessUtils.extractItemFromWitness(witness0, 1); // skip musig signature

        // Unlocking witness script is consisted of a fixed prefix and suffix part with a variable txId of the transaction to be replaced in between
        uint256 prefixLen = replacePrefix.length;
        uint256 suffixLen = replaceSuffix.length;
        // Assert if the parsed script is of the correct length, and that it starts with the prefix and ends with the suffix
        require(script.length == prefixLen + 32 + suffixLen, "Invalid script length");
        bytes memory _replacePrefix = script.slice(0, prefixLen);
        require(isBytesEqual(_replacePrefix, replacePrefix), "Invalid replace script prefix");
        bytes memory _replaceSuffix = script.slice(script.length - suffixLen, suffixLen);
        require(isBytesEqual(_replaceSuffix, replaceSuffix), "Invalid replace script suffix");

        bytes32 txId = extractTxId(script);
        require(txId == txIdToReplace, "Invalid txId to replace provided");

        emit DepositReplaced(idToReplace, txId, newTxId);
    }

    function validateAndCheckInclusion(Transaction calldata txn, MerkleProof calldata proof) internal view returns (bytes32, uint256) {
        bytes32 wtxId = WitnessUtils.calculateWtxId(txn.version, txn.flag, txn.vin, txn.vout, txn.witness, txn.locktime);
        require(BTCUtils.validateVin(txn.vin), "Vin is not properly formatted");
        require(BTCUtils.validateVout(txn.vout), "Vout is not properly formatted");
        
        (, uint256 nIns) = BTCUtils.parseVarInt(txn.vin);
        // Number of inputs == number of witnesses
        require(WitnessUtils.validateWitness(txn.witness, nIns), "Witness is not properly formatted");

        require(LIGHT_CLIENT.verifyInclusion(proof.blockHeight, wtxId, proof.intermediateNodes, proof.index), "Transaction is not in block");

        return (wtxId, nIns);
    }

    function extractRecipientAddress(bytes memory _script) internal view returns (address) {
        uint256 offset = depositPrefix.length;
        bytes20 _addr = bytes20(_script.slice(offset, 20));
        return address(uint160(_addr));
    }

    function extractTxId(bytes memory _script) internal view returns (bytes32) {
        uint256 offset = replacePrefix.length;
        bytes32 txId = bytesToBytes32(_script.slice(offset, 32));
        return txId;
    }

    function getAggregatedKey() public view returns (bytes memory) {
        return depositPrefix.slice(2, 32);
    }

    function pause() external onlyOwnerOrOperator {
        _pause();
    }

    function unpause() external onlyOwnerOrOperator {
        _unpause();
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
        for (uint256 i = offset - 32; i < len; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }

        return true;
    }

    function bytesToBytes32(bytes memory _source) internal pure returns (bytes32 result) {
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

    /// @notice Verifies a P2TR signature by reconstructing the message hash and checking it against the provided signature, see BIP-341
    function verifySigInTx(bytes memory input, bytes memory outputs, bytes memory witness0, bytes4 version, bytes4 locktime, bytes32 shaScriptPubkeys) internal view {
        bytes32 shaPrevouts = sha256(input.extractOutpoint());
        bytes32 shaAmounts = sha256(abi.encodePacked(bytes8(BTCUtils.reverseUint64(uint64(depositAmount/(SAT_TO_WEI)))))); // 1000000000 in LE
        bytes32 shaSequences = sha256(abi.encodePacked(input.extractSequenceLEWitness()));
        bytes32 shaOutputs = sha256(abi.encodePacked(outputs));
        bytes memory script = witness0.extractItemFromWitness(1);
        bytes memory controlBlock = witness0.extractItemFromWitness(2);
        // First byte of the parsed control block is the length of it so it is skipped to get the actual first byte
        // We can safely assume the control block compact size to be single byte as the depth of taproot tree is 1 both for `deposit` and `replaceDeposit`
        bytes1 leafVersion = controlBlock[1] & 0xFE;
        bytes32 tapleafHash = taggedHash("TapLeaf", (abi.encodePacked(leafVersion, script)));
        bytes memory message = abi.encodePacked(EPOCH, SIGHASH_DEFAULT_HASH_TYPE, version, locktime, shaPrevouts, shaAmounts, shaScriptPubkeys, shaSequences, shaOutputs, SPEND_TYPE_EXT, INPUT_INDEX, tapleafHash, KEY_VERSION, CODESEP_POS);
        bytes32 messageHash = taggedHash("TapSighash", message);
        bytes memory signatureWithLen = witness0.extractItemFromWitness(0);
        bytes memory signature = signatureWithLen.slice(1, signatureWithLen.length - 1);
        bytes memory aggregatedKey = getAggregatedKey();
        require(isSchnorrSigValid(aggregatedKey, messageHash, signature), "Invalid signature");
    }

    /// @notice Checks if a Schnorr signature is valid by calling Citrea's Schnorr signature verification precompile at 0x200
    function isSchnorrSigValid(bytes memory pubKey, bytes32 messageHash, bytes memory signature) internal view returns (bool isValid) {
        require(signature.length == 64 || signature.length == 65, "Invalid signature length");
        signature = signature.slice(0, 64);
        (bool success, bytes memory result) = address(SCHNORR_VERIFIER_PRECOMPILE).staticcall(abi.encodePacked(pubKey, messageHash, signature));
        isValid = success && (result.length == 32) && (result[31] == 0x01);
    }

    function taggedHash(string memory tag, bytes memory message) internal pure returns (bytes32) {
        bytes32 tagHash = sha256(bytes(tag));
        return sha256(abi.encodePacked(tagHash, tagHash, message));
    }
}