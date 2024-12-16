#[cfg(all(feature = "arbitrary", feature = "native"))]
mod fuzz;
mod genesis;
mod hooks;
pub use genesis::*;
#[cfg(feature = "native")]
mod query;
#[cfg(feature = "native")]
pub use query::*;
#[cfg(all(test, feature = "native"))]
mod tests;

pub use hooks::AccountsTxHook;
use sov_modules_api::{Context, ModuleInfo, SoftConfirmationModuleCallError, WorkingSet};

impl<C: Context> FromIterator<C::PublicKey> for AccountConfig<C> {
    fn from_iter<T: IntoIterator<Item = C::PublicKey>>(iter: T) -> Self {
        Self {
            pub_keys: iter.into_iter().collect(),
        }
    }
}

/// An account on the rollup.
#[derive(borsh::BorshDeserialize, borsh::BorshSerialize, Debug, PartialEq, Copy, Clone)]
pub struct Account<C: Context> {
    /// The address of the account.
    pub addr: C::Address,
    /// The current nonce value associated with the account.
    pub nonce: u64,
}

/// A module responsible for managing accounts on the rollup.
#[cfg_attr(feature = "native", derive(sov_modules_api::ModuleCallJsonSchema))]
#[derive(ModuleInfo, Clone)]
#[cfg_attr(feature = "arbitrary", derive(Debug))]
pub struct Accounts<C: Context> {
    /// The address of the sov-accounts module.
    #[address]
    pub address: C::Address,

    /// Mapping from an account address to a corresponding public key.
    #[state]
    pub(crate) public_keys: sov_modules_api::StateMap<C::Address, C::PublicKey>,

    /// Mapping from a public key to a corresponding account.
    #[state]
    pub(crate) accounts: sov_modules_api::StateMap<C::PublicKey, Account<C>>,
}

impl<C: Context> sov_modules_api::Module for Accounts<C> {
    type Context = C;

    type Config = AccountConfig<C>;

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
