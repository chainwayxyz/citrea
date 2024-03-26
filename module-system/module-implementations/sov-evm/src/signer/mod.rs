use std::collections::HashMap;

use alloy_primitives::address;
use reth_primitives::{
    sign_message, Address, Signature, Transaction, TransactionSigned, B256, U256,
};
use secp256k1::{PublicKey, SecretKey};

use crate::error::rpc::SignError;

/// This is a special signature to force tx.signer to be set to SYSTEM_SIGNER
pub const SYSTEM_SIGNATURE: Signature = Signature {
    r: U256::ZERO,
    s: U256::ZERO,
    odd_y_parity: false,
};

/// This is a special system address to indicate a tx is called by system not by a user/contract.
pub const SYSTEM_SIGNER: Address = address!("deaddeaddeaddeaddeaddeaddeaddeaddeaddead");

/// Ethereum transaction signer.
#[derive(Clone)]
pub struct DevSigner {
    signers: HashMap<Address, SecretKey>,
}

impl DevSigner {
    /// Creates a new DevSigner.
    pub fn new(secret_keys: Vec<SecretKey>) -> Self {
        let mut signers = HashMap::with_capacity(secret_keys.len());

        for sk in secret_keys {
            let public_key = PublicKey::from_secret_key(secp256k1::SECP256K1, &sk);
            let address = reth_primitives::public_key_to_address(public_key);

            signers.insert(address, sk);
        }

        Self { signers }
    }

    /// Signs an ethereum transaction.
    pub fn sign_transaction(
        &self,
        transaction: Transaction,
        address: Address,
    ) -> Result<TransactionSigned, SignError> {
        let tx_signature_hash = transaction.signature_hash();
        let signer = self.signers.get(&address).ok_or(SignError::NoAccount)?;

        let signature = sign_message(B256::from_slice(signer.as_ref()), tx_signature_hash)
            .map_err(|_| SignError::CouldNotSign)?;

        Ok(TransactionSigned::from_transaction_and_signature(
            transaction,
            signature,
        ))
    }

    /// Signs an system ethereum transaction.
    ///
    /// # Safety
    /// This should be called only for transactions we want to be marked as "executed by system".
    pub unsafe fn sign_system_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<TransactionSigned, SignError> {
        Ok(TransactionSigned::from_transaction_and_signature(
            transaction,
            SYSTEM_SIGNATURE,
        ))
    }

    /// List of signers.
    pub fn signers(&self) -> Vec<Address> {
        self.signers.keys().copied().collect()
    }
}
