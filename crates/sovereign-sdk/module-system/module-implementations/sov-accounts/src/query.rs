//! Defines rpc queries exposed by the accounts module, along with the relevant types
use borsh::BorshDeserialize;
use jsonrpsee::core::RpcResult;
use sov_modules_api::macros::rpc_gen;
use sov_modules_api::{AddressBech32, SpecId, StateMapAccessor, WorkingSet};

use crate::{Account, Accounts};

/// This is the response returned from the accounts_getAccount endpoint.
#[derive(Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, Clone)]
pub enum Response {
    /// The account corresponding to the given public key exists.
    AccountExists {
        /// The address of the account,
        addr: AddressBech32,
        /// The nonce of the account.
        nonce: u64,
    },
    /// The account corresponding to the given public key does not exist.
    AccountEmpty,
}

#[rpc_gen(client, server, namespace = "accounts")]
impl<C: sov_modules_api::Context> Accounts<C> {
    #[rpc_method(name = "getAccount")]
    /// Get the account corresponding to the given public key.
    pub fn get_account(
        &self,
        pub_key: Vec<u8>,
        spec_id: SpecId,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> RpcResult<Response> {
        let response = if spec_id >= SpecId::Fork2 {
            match self.accounts.get(&pub_key, working_set) {
                Some(Account { addr, nonce }) => Response::AccountExists {
                    addr: addr.into(),
                    nonce,
                },
                None => Response::AccountEmpty,
            }
        } else {
            match self.accounts_pre_fork2.get(
                &C::PublicKey::try_from_slice(pub_key.as_slice())
                    .expect("Pub key is not a valid dalek pub key"),
                working_set,
            ) {
                Some(Account { addr, nonce }) => Response::AccountExists {
                    addr: addr.into(),
                    nonce,
                },
                None => Response::AccountEmpty,
            }
        };

        Ok(response)
    }
}
