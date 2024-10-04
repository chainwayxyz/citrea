mod filter;
mod log_utils;
mod responses;
mod tracing_utils;

pub use filter::*;
pub use log_utils::*;
pub use responses::*;
use reth_primitives::{keccak256, Address, U256};
use reth_rpc_eth_types::{EthApiError, EthResult};
use reth_rpc_types::state::AccountOverride;
use revm::Database;
pub(crate) use tracing_utils::*;

use crate::db::EvmDb;

#[cfg(feature = "native")]
/// Applies a single [`AccountOverride`] to the [`EvmDb`].
pub(crate) fn apply_account_override<'a, C: sov_modules_api::Context>(
    account: Address,
    account_override: AccountOverride,
    db: &mut EvmDb<'a, C>,
) -> EthResult<()> {
    // we need to fetch the account via the `DatabaseRef` to not update the state of the account,
    // which is modified via `Database::basic_ref`
    let mut account_info = db.basic(account)?.unwrap_or_default();

    if let Some(nonce) = account_override.nonce {
        account_info.nonce = nonce;
    }
    if let Some(code) = account_override.code {
        account_info.code_hash = keccak256(code);
    }
    if let Some(balance) = account_override.balance {
        account_info.balance = balance;
    }

    db.override_account(&account, account_info.into());

    // We ensure that not both state and state_diff are set.
    // If state is set, we must mark the account as "NewlyCreated", so that the old storage
    // isn't read from
    match (account_override.state, account_override.state_diff) {
        (Some(_), Some(_)) => return Err(EthApiError::BothStateAndStateDiffInOverride(account)),
        (None, None) => {
            // nothing to do
        }
        (Some(new_account_state), None) => {
            db.override_replace_account_storage(
                &account,
                new_account_state
                    .into_iter()
                    .map(|(slot, value)| {
                        (U256::from_be_bytes(slot.0), U256::from_be_bytes(value.0))
                    })
                    .collect(),
            );
        }
        (None, Some(account_state_diff)) => {
            db.override_insert_account_storage(&account, account_state_diff);
        }
    };

    Ok(())
}
