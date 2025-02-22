mod genesis;
mod hooks;
use borsh::BorshSerialize;
pub use genesis::*;
#[cfg(feature = "native")]
mod query;
#[cfg(feature = "native")]
pub use query::*;
#[cfg(all(test, feature = "native"))]
mod tests;

pub use hooks::AccountsTxHook;
use sov_modules_api::default_signature::DefaultPublicKey;
use sov_modules_api::{Address, Context, ModuleInfo, SoftConfirmationModuleCallError, WorkingSet};
use sov_state::codec::BorshCodec;
use sov_state::storage::StateValueCodec;

impl FromIterator<Vec<u8>> for AccountConfig {
    fn from_iter<T: IntoIterator<Item = Vec<u8>>>(iter: T) -> Self {
        Self {
            pub_keys: iter.into_iter().collect(),
        }
    }
}

/// An account on the rollup.
#[derive(borsh::BorshDeserialize, borsh::BorshSerialize, Debug, PartialEq, Copy, Clone)]
pub struct Account {
    /// The address of the account.
    pub addr: Address,
    /// The current nonce value associated with the account.
    pub nonce: u64,
}

impl StateValueCodec<Account> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &Account) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 8);
        BorshSerialize::serialize(value, &mut buf).unwrap();
        buf
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<Account, Self::Error> {
        borsh::from_slice(bytes)
    }
}

/// A module responsible for managing accounts on the rollup.
#[cfg_attr(feature = "native", derive(sov_modules_api::ModuleCallJsonSchema))]
#[derive(ModuleInfo, Clone)]
pub struct Accounts<C: Context> {
    /// The address of the sov-accounts module.
    #[address]
    pub address: C::Address,

    /// Mapping from an account address to a corresponding public key.
    #[state(rename = "public_keys_post_fork2")]
    pub(crate) public_keys: sov_modules_api::StateMap<Address, Vec<u8>>,

    /// Mapping from an account address to a corresponding public key used before fork2.
    /// This uses address to public key object directly
    #[state(rename = "public_keys")]
    pub(crate) public_keys_pre_fork2: sov_modules_api::StateMap<Address, DefaultPublicKey>,

    /// Mapping from a public key to a corresponding account.
    #[state(rename = "accounts_post_fork2")]
    pub(crate) accounts: sov_modules_api::StateMap<Vec<u8>, Account>,

    /// Mapping from a public key to a corresponding account.
    #[state(rename = "accounts")]
    pub(crate) accounts_pre_fork2: sov_modules_api::StateMap<DefaultPublicKey, Account>,
}

impl<C: Context> sov_modules_api::Module for Accounts<C> {
    type Context = C;

    type Config = AccountConfig;

    type CallMessage = ();

    fn genesis(&self, config: &Self::Config, working_set: &mut WorkingSet<C::Storage>) {
        self.init_module(config, working_set)
    }

    fn call(
        &mut self,
        _msg: Self::CallMessage,
        _context: &Self::Context,
        _working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<sov_modules_api::CallResponse, SoftConfirmationModuleCallError> {
        Ok(sov_modules_api::CallResponse::default())
    }
}
