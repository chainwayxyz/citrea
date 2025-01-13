use alloy_consensus::{TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy};
use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_primitives::{Address, Bytes, ChainId, Parity, Signature, TxHash, TxKind, B256, U256};
use alloy_rpc_types::AccessList;
use reth_primitives::{Transaction, TransactionSigned};
use serde::{Deserialize, Serialize};

/// To be used with `Option<CompactPlaceholder>` to place or replace one bit on the bitflag struct.
pub(crate) type CompactPlaceholder = ();

// Legacy transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct DoNotUseTxLegacy {
    /// Added as EIP-155: Simple replay attack protection
    pub chain_id: Option<ChainId>,
    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    pub nonce: u64,
    /// A scalar value equal to the number of
    /// Wei to be paid per unit of gas for all computation
    /// costs incurred as a result of the execution of this transaction; formally Tp.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    pub gas_price: u128,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    pub gas_limit: u64,
    /// The 160-bit address of the message call’s recipient or, for a contract creation
    /// transaction, ∅, used here to denote the only member of B0 ; formally Tt.
    pub to: TxKind,
    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account; formally Tv.
    pub value: U256,
    /// Input has two uses depending if transaction is Create or Call (if `to` field is None or
    /// Some). pub init: An unlimited size byte array specifying the
    /// EVM-code for the account initialisation procedure CREATE,
    /// data: An unlimited size byte array specifying the
    /// input data of the message call, formally Td.
    pub input: Bytes,
}

impl From<DoNotUseTxLegacy> for TxLegacy {
    fn from(tx: DoNotUseTxLegacy) -> Self {
        let DoNotUseTxLegacy {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            input,
        } = tx;

        TxLegacy {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            input,
        }
    }
}

/// Transaction with an [`AccessList`] ([EIP-2930](https://eips.ethereum.org/EIPS/eip-2930)).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct DoNotUseTxEip2930 {
    /// Added as EIP-155: Simple replay attack protection
    pub chain_id: ChainId,

    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    pub nonce: u64,

    /// A scalar value equal to the number of
    /// Wei to be paid per unit of gas for all computation
    /// costs incurred as a result of the execution of this transaction; formally Tp.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    pub gas_price: u128,

    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    pub gas_limit: u64,

    /// The 160-bit address of the message call’s recipient or, for a contract creation
    /// transaction, ∅, used here to denote the only member of B0 ; formally Tt.
    pub to: TxKind,

    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account; formally Tv.
    pub value: U256,

    /// The accessList specifies a list of addresses and storage keys;
    /// these addresses and storage keys are added into the `accessed_addresses`
    /// and `accessed_storage_keys` global sets (introduced in EIP-2929).
    /// A gas cost is charged, though at a discount relative to the cost of
    /// accessing outside the list.
    pub access_list: AccessList,

    /// Input has two uses depending if the transaction `to` field is [`TxKind::Create`] or
    /// [`TxKind::Call`].
    ///
    /// Input as init code, or if `to` is [`TxKind::Create`]: An unlimited size byte array
    /// specifying the EVM-code for the account initialisation procedure `CREATE`
    ///
    /// Input as data, or if `to` is [`TxKind::Call`]: An unlimited size byte array specifying the
    /// input data of the message call, formally Td.
    pub input: Bytes,
}

impl From<DoNotUseTxEip2930> for TxEip2930 {
    fn from(tx: DoNotUseTxEip2930) -> Self {
        let DoNotUseTxEip2930 {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            access_list,
            input,
        } = tx;

        TxEip2930 {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            access_list,
            input,
        }
    }
}

/// A transaction with a priority fee ([EIP-1559](https://eips.ethereum.org/EIPS/eip-1559)).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct DoNotUseTxEip1559 {
    /// Added as EIP-155: Simple replay attack protection
    pub chain_id: ChainId,

    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    pub nonce: u64,

    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    pub gas_limit: u64,

    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasFeeCap`
    pub max_fee_per_gas: u128,

    /// Max Priority fee that transaction is paying
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasTipCap`
    pub max_priority_fee_per_gas: u128,

    /// The 160-bit address of the message call’s recipient or, for a contract creation
    /// transaction, ∅, used here to denote the only member of B0 ; formally Tt.
    pub to: TxKind,

    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account; formally Tv.
    pub value: U256,

    /// The accessList specifies a list of addresses and storage keys;
    /// these addresses and storage keys are added into the `accessed_addresses`
    /// and `accessed_storage_keys` global sets (introduced in EIP-2929).
    /// A gas cost is charged, though at a discount relative to the cost of
    /// accessing outside the list.
    pub access_list: AccessList,

    /// Input has two uses depending if the transaction `to` field is [`TxKind::Create`] or
    /// [`TxKind::Call`].
    ///
    /// Input as init code, or if `to` is [`TxKind::Create`]: An unlimited size byte array
    /// specifying the EVM-code for the account initialisation procedure `CREATE`
    ///
    /// Input as data, or if `to` is [`TxKind::Call`]: An unlimited size byte array specifying the
    /// input data of the message call, formally Td.
    pub input: Bytes,
}

impl From<DoNotUseTxEip1559> for TxEip1559 {
    fn from(tx: DoNotUseTxEip1559) -> Self {
        let DoNotUseTxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to,
            value,
            access_list,
            input,
        } = tx;

        TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to,
            value,
            access_list,
            input,
        }
    }
}

/// [EIP-4844 Blob Transaction](https://eips.ethereum.org/EIPS/eip-4844#blob-transaction)
///
/// A transaction with blob hashes and max blob fee
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct DoNotUseTxEip4844 {
    /// Added as EIP-155: Simple replay attack protection
    pub chain_id: ChainId,

    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    pub nonce: u64,

    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    pub gas_limit: u64,

    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasFeeCap`
    pub max_fee_per_gas: u128,

    /// Max Priority fee that transaction is paying
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasTipCap`
    pub max_priority_fee_per_gas: u128,

    /// TODO(debt): this should be removed if we break the DB.
    /// Makes sure that the Compact bitflag struct has one bit after the above field:
    /// <https://github.com/paradigmxyz/reth/pull/8291#issuecomment-2117545016>
    pub placeholder: Option<CompactPlaceholder>,

    /// The 160-bit address of the message call’s recipient.
    pub to: Address,

    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account; formally Tv.
    pub value: U256,

    /// The accessList specifies a list of addresses and storage keys;
    /// these addresses and storage keys are added into the `accessed_addresses`
    /// and `accessed_storage_keys` global sets (introduced in EIP-2929).
    /// A gas cost is charged, though at a discount relative to the cost of
    /// accessing outside the list.
    pub access_list: AccessList,

    /// It contains a vector of fixed size hash(32 bytes)
    pub blob_versioned_hashes: Vec<B256>,

    /// Max fee per data gas
    ///
    /// aka BlobFeeCap or blobGasFeeCap
    pub max_fee_per_blob_gas: u128,

    /// Unlike other transaction types, where the `input` field has two uses depending on whether
    /// or not the `to` field is [`Create`](crate::TxKind::Create) or
    /// [`Call`](crate::TxKind::Call), EIP-4844 transactions cannot be
    /// [`Create`](crate::TxKind::Create) transactions.
    ///
    /// This means the `input` field has a single use, as data: An unlimited size byte array
    /// specifying the input data of the message call, formally Td.
    pub input: Bytes,
}

impl From<DoNotUseTxEip4844> for TxEip4844 {
    fn from(value: DoNotUseTxEip4844) -> Self {
        TxEip4844 {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_limit: value.gas_limit,
            max_fee_per_gas: value.max_fee_per_gas,
            max_priority_fee_per_gas: value.max_priority_fee_per_gas,
            to: value.to,
            value: value.value,
            access_list: value.access_list,
            blob_versioned_hashes: value.blob_versioned_hashes,
            max_fee_per_blob_gas: value.max_fee_per_blob_gas,
            input: value.input,
        }
    }
}

/// r, s: Values corresponding to the signature of the
/// transaction and used to determine the sender of
/// the transaction; formally Tr and Ts. This is expanded in Appendix F of yellow paper.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct DoNotUseSignature {
    /// The R field of the signature; the point on the curve.
    pub r: U256,
    /// The S field of the signature; the point on the curve.
    pub s: U256,
    /// yParity: Signature Y parity; formally Ty
    ///
    /// WARNING: if it's deprecated in favor of `alloy_primitives::Signature` be sure that parity
    /// storage deser matches.
    pub odd_y_parity: bool,
}

impl From<DoNotUseSignature> for Signature {
    fn from(value: DoNotUseSignature) -> Self {
        Signature::new(value.r, value.s, Parity::Parity(value.odd_y_parity))
    }
}

/// An internal wrapper around an `Option<u64>` for optional nonces.
///
/// In EIP-7702 the nonce is encoded as a list of either 0 or 1 items, where 0 items means that no
/// nonce was specified (i.e. `None`). If there is 1 item, this is the same as `Some`.
///
/// The wrapper type is used for RLP encoding and decoding.
#[derive(Default, Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct DoNotUseOptionalNonce(Option<u64>);

/// An unsigned EIP-7702 authorization.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct DoNotUseAuthorization {
    /// The chain ID of the authorization.
    pub chain_id: ChainId,
    /// The address of the authorization.
    pub address: Address,
    /// The nonce for the authorization.
    pub nonce: DoNotUseOptionalNonce,
}

impl From<DoNotUseAuthorization> for Authorization {
    fn from(value: DoNotUseAuthorization) -> Self {
        Authorization {
            chain_id: U256::from(value.chain_id),
            address: value.address,
            nonce: value.nonce.0.unwrap_or_default(),
        }
    }
}

/// A signed EIP-7702 authorization.
/// Signature struct is different
/// Authorization struct ChainID field used to be u64, now U256
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct DoNotUseSignedAuthorization {
    inner: DoNotUseAuthorization,
    signature: DoNotUseSignature,
}

impl From<DoNotUseSignedAuthorization> for SignedAuthorization {
    fn from(value: DoNotUseSignedAuthorization) -> Self {
        Authorization {
            chain_id: U256::from(value.inner.chain_id),
            address: value.inner.address,
            nonce: value.inner.nonce.0.unwrap_or_default(),
        }
        .into_signed(value.signature.into())
    }
}

/// [EIP-7702 Set Code Transaction](https://eips.ethereum.org/EIPS/eip-7702)
///
/// Set EOA account code for one transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct DoNotUseTxEip7702 {
    /// Added as EIP-155: Simple replay attack protection
    pub chain_id: ChainId,
    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    pub nonce: u64,
    /// A scalar value equal to the number of
    /// Wei to be paid per unit of gas for all computation
    /// costs incurred as a result of the execution of this transaction; formally Tp.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    pub gas_limit: u64,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasFeeCap`
    pub max_fee_per_gas: u128,
    /// Max Priority fee that transaction is paying
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasTipCap`
    pub max_priority_fee_per_gas: u128,
    /// The 160-bit address of the message call’s recipient or, for a contract creation
    /// transaction, ∅, used here to denote the only member of B0 ; formally Tt.
    pub to: TxKind,
    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account; formally Tv.
    pub value: U256,
    /// The accessList specifies a list of addresses and storage keys;
    /// these addresses and storage keys are added into the `accessed_addresses`
    /// and `accessed_storage_keys` global sets (introduced in EIP-2929).
    /// A gas cost is charged, though at a discount relative to the cost of
    /// accessing outside the list.
    pub access_list: AccessList,
    /// Authorizations are used to temporarily set the code of its signer to
    /// the code referenced by `address`. These also include a `chain_id` (which
    /// can be set to zero and not evaluated) as well as an optional `nonce`.
    pub authorization_list: Vec<DoNotUseSignedAuthorization>,
    /// Input has two uses depending if the transaction `to` field is [`TxKind::Create`] or
    /// [`TxKind::Call`].
    ///
    /// Input as init code, or if `to` is [`TxKind::Create`]: An unlimited size byte array
    /// specifying the EVM-code for the account initialisation procedure `CREATE`
    ///
    /// Input as data, or if `to` is [`TxKind::Call`]: An unlimited size byte array specifying the
    /// input data of the message call, formally Td.
    pub input: Bytes,
}

impl From<DoNotUseTxEip7702> for TxEip7702 {
    fn from(value: DoNotUseTxEip7702) -> Self {
        let addr: Option<Address> = value.to.into();
        let list = value
            .authorization_list
            .iter()
            .map(|v| v.clone().into())
            .collect::<Vec<SignedAuthorization>>();

        TxEip7702 {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_limit: value.gas_limit,
            max_fee_per_gas: value.max_fee_per_gas,
            max_priority_fee_per_gas: value.max_priority_fee_per_gas,
            to: addr.unwrap(),
            value: value.value,
            access_list: value.access_list,
            authorization_list: list,
            input: value.input,
        }
    }
}

/// A raw transaction.
///
/// Transaction types were introduced in [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DoNotUseTransaction {
    /// Legacy transaction (type `0x0`).
    ///
    /// Traditional Ethereum transactions, containing parameters `nonce`, `gasPrice`, `gasLimit`,
    /// `to`, `value`, `data`, `v`, `r`, and `s`.
    ///
    /// These transactions do not utilize access lists nor do they incorporate EIP-1559 fee market
    /// changes.
    Legacy(DoNotUseTxLegacy),
    /// Transaction with an [`AccessList`] ([EIP-2930](https://eips.ethereum.org/EIPS/eip-2930)), type `0x1`.
    ///
    /// The `accessList` specifies an array of addresses and storage keys that the transaction
    /// plans to access, enabling gas savings on cross-contract calls by pre-declaring the accessed
    /// contract and storage slots.
    Eip2930(DoNotUseTxEip2930),
    /// A transaction with a priority fee ([EIP-1559](https://eips.ethereum.org/EIPS/eip-1559)), type `0x2`.
    ///
    /// Unlike traditional transactions, EIP-1559 transactions use an in-protocol, dynamically
    /// changing base fee per gas, adjusted at each block to manage network congestion.
    ///
    /// - `maxPriorityFeePerGas`, specifying the maximum fee above the base fee the sender is
    ///   willing to pay
    /// - `maxFeePerGas`, setting the maximum total fee the sender is willing to pay.
    ///
    /// The base fee is burned, while the priority fee is paid to the miner who includes the
    /// transaction, incentivizing miners to include transactions with higher priority fees per
    /// gas.
    Eip1559(DoNotUseTxEip1559),
    /// Shard Blob Transactions ([EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)), type `0x3`.
    ///
    /// Shard Blob Transactions introduce a new transaction type called a blob-carrying transaction
    /// to reduce gas costs. These transactions are similar to regular Ethereum transactions but
    /// include additional data called a blob.
    ///
    /// Blobs are larger (~125 kB) and cheaper than the current calldata, providing an immutable
    /// and read-only memory for storing transaction data.
    ///
    /// EIP-4844, also known as proto-danksharding, implements the framework and logic of
    /// danksharding, introducing new transaction formats and verification rules.
    Eip4844(DoNotUseTxEip4844),
    /// EOA Set Code Transactions ([EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)), type `0x4`.
    ///
    /// EOA Set Code Transactions give the ability to temporarily set contract code for an
    /// EOA for a single transaction. This allows for temporarily adding smart contract
    /// functionality to the EOA.
    Eip7702(DoNotUseTxEip7702),
}

impl From<DoNotUseTransaction> for Transaction {
    fn from(value: DoNotUseTransaction) -> Self {
        match value {
            DoNotUseTransaction::Legacy(tx) => Transaction::Legacy(tx.into()),
            DoNotUseTransaction::Eip2930(tx) => Transaction::Eip2930(tx.into()),
            DoNotUseTransaction::Eip1559(tx) => Transaction::Eip1559(tx.into()),
            DoNotUseTransaction::Eip4844(tx) => Transaction::Eip4844(tx.into()),
            DoNotUseTransaction::Eip7702(tx) => Transaction::Eip7702(tx.into()),
        }
    }
}

/// Signed transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DoNotUseTransactionSigned {
    /// Transaction hash
    pub hash: TxHash,
    /// The transaction signature values
    pub signature: DoNotUseSignature,
    /// Raw transaction info
    pub transaction: DoNotUseTransaction,
}

impl From<DoNotUseTransactionSigned> for TransactionSigned {
    fn from(value: DoNotUseTransactionSigned) -> Self {
        TransactionSigned {
            hash: value.hash,
            signature: value.signature.into(),
            transaction: value.transaction.into(),
        }
    }
}
