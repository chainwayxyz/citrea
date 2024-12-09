use rand::rngs::StdRng;
use rand::SeedableRng;
use reth_primitives::{
    Address, Bytes as RethBytes, Transaction as RethTransaction, TxEip1559 as RethTxEip1559,
    TxEip4844 as RethTxEip4844, TxKind, B256, U256,
};
use secp256k1::{PublicKey, SecretKey};

use crate::evm::RlpEvmTransaction;
use crate::signer::DevSigner;
use crate::tests::DEFAULT_CHAIN_ID;
use crate::SignError;

/// ETH transactions signer used in tests.
pub(crate) struct TestSigner {
    signer: DevSigner,
    address: Address,
}

impl TestSigner {
    /// Creates a new signer.
    pub(crate) fn new(secret_key: SecretKey) -> Self {
        let public_key = PublicKey::from_secret_key(secp256k1::SECP256K1, &secret_key);
        let address = reth_primitives::public_key_to_address(public_key);
        Self {
            signer: DevSigner::new(vec![secret_key]),
            address,
        }
    }

    /// Creates a new signer with random private key.
    pub(crate) fn new_random() -> Self {
        let mut rng = StdRng::seed_from_u64(22);
        let secret_key = SecretKey::new(&mut rng);
        Self::new(secret_key)
    }

    /// Address of the transaction signer.
    pub(crate) fn address(&self) -> Address {
        self.address
    }

    /// Signs default Eip1559 transaction with to, data and nonce overridden.
    pub(crate) fn sign_default_transaction(
        &self,
        to: TxKind,
        data: Vec<u8>,
        nonce: u64,
        value: u128,
    ) -> Result<RlpEvmTransaction, SignError> {
        self.sign_default_transaction_with_fee(to, data, nonce, value, 100000000000u128)
    }

    /// Signs default Eip1559 transaction with to, data and nonce overridden.
    pub(crate) fn sign_default_transaction_with_fee(
        &self,
        to: TxKind,
        data: Vec<u8>,
        nonce: u64,
        value: u128,
        max_fee_per_gas: u128,
    ) -> Result<RlpEvmTransaction, SignError> {
        let reth_tx = RethTxEip1559 {
            to,
            input: RethBytes::from(data),
            nonce,
            value: U256::from(value),
            chain_id: DEFAULT_CHAIN_ID,
            gas_limit: 1_000_000u64,
            max_fee_per_gas,
            ..Default::default()
        };

        let reth_tx = RethTransaction::Eip1559(reth_tx);
        let signed = self.signer.sign_transaction(reth_tx, self.address)?;

        Ok(RlpEvmTransaction {
            rlp: signed.envelope_encoded().to_vec(),
        })
    }

    /// Signs default Eip1559 transaction with to, data, gas limit and nonce overridden.
    pub(crate) fn sign_default_transaction_with_fee_and_gas_limit(
        &self,
        to: TxKind,
        data: Vec<u8>,
        nonce: u64,
        value: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
    ) -> Result<RlpEvmTransaction, SignError> {
        let reth_tx = RethTxEip1559 {
            to,
            input: RethBytes::from(data),
            nonce,
            value: U256::from(value),
            chain_id: DEFAULT_CHAIN_ID,
            gas_limit,
            max_fee_per_gas,
            ..Default::default()
        };

        let reth_tx = RethTransaction::Eip1559(reth_tx);
        let signed = self.signer.sign_transaction(reth_tx, self.address)?;

        Ok(RlpEvmTransaction {
            rlp: signed.envelope_encoded().to_vec(),
        })
    }

    /// Signs default Eip1559 transaction with to, data and nonce overridden.
    pub(crate) fn sign_default_transaction_with_priority_fee(
        &self,
        to: TxKind,
        data: Vec<u8>,
        nonce: u64,
        value: u128,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> Result<RlpEvmTransaction, SignError> {
        let reth_tx = RethTxEip1559 {
            to,
            input: RethBytes::from(data),
            nonce,
            value: U256::from(value),
            chain_id: DEFAULT_CHAIN_ID,
            gas_limit: 1_000_000u64,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            ..Default::default()
        };

        let reth_tx = RethTransaction::Eip1559(reth_tx);
        let signed = self.signer.sign_transaction(reth_tx, self.address)?;

        Ok(RlpEvmTransaction {
            rlp: signed.envelope_encoded().to_vec(),
        })
    }

    pub(crate) fn sign_blob_transaction(
        &self,
        to: Address,
        blob_versioned_hashes: Vec<B256>,
        nonce: u64,
    ) -> Result<RlpEvmTransaction, SignError> {
        let reth_tx = RethTxEip4844 {
            to,
            nonce,
            chain_id: DEFAULT_CHAIN_ID,
            blob_versioned_hashes,
            max_fee_per_blob_gas: 100000000000u128,
            max_fee_per_gas: 100000000000u128,
            gas_limit: 1_000_000u64,
            ..Default::default()
        };

        let reth_tx = RethTransaction::Eip4844(reth_tx);
        let signed = self.signer.sign_transaction(reth_tx, self.address)?;

        Ok(RlpEvmTransaction {
            rlp: signed.envelope_encoded().to_vec(),
        })
    }
}
