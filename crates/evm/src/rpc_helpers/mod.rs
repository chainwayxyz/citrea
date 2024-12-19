use std::collections::HashMap;

use alloy_primitives::{keccak256, Address};
use alloy_rpc_types::state::AccountOverride;
use alloy_rpc_types::BlockOverrides;
pub use filter::*;
pub use log_utils::*;
pub use responses::*;
use reth_rpc_eth_types::{EthApiError, EthResult};
use revm::Database;

mod filter;
mod log_utils;
mod responses;
mod tracing_utils;

#[cfg(feature = "native")]
use revm::primitives::BlockEnv;
pub(crate) use tracing_utils::*;

use crate::db::EvmDb;

#[cfg(feature = "native")]
/// Applies all instances [`AccountOverride`] to the [`EvmDb`].
pub(crate) fn apply_state_overrides<C: sov_modules_api::Context>(
    state_overrides: HashMap<Address, AccountOverride, alloy_primitives::map::FbBuildHasher<20>>,
    db: &mut EvmDb<C>,
) -> EthResult<()> {
    for (address, account_overrides) in state_overrides {
        apply_account_override(address, account_overrides, db)?;
    }

    Ok(())
}

#[cfg(feature = "native")]
/// Applies a single [`AccountOverride`] to the [`EvmDb`].
pub(crate) fn apply_account_override<C: sov_modules_api::Context>(
    account: Address,
    account_override: AccountOverride,
    db: &mut EvmDb<C>,
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
            db.override_set_account_storage(&account, new_account_state);
        }
        (None, Some(account_state_diff)) => {
            db.override_set_account_storage(&account, account_state_diff);
        }
    };

    Ok(())
}

#[cfg(feature = "native")]
/// Applies all instances of [`BlockOverride`] to the [`EvmDb`].
pub(crate) fn apply_block_overrides<C: sov_modules_api::Context>(
    block_env: &mut BlockEnv,
    block_overrides: &mut BlockOverrides,
    db: &mut EvmDb<C>,
) {
    use alloy_primitives::U256;

    if let Some(block_hashes) = block_overrides.block_hash.take() {
        // override block hashes
        for (num, hash) in block_hashes {
            db.override_block_hash(num, hash);
        }
    }

    let BlockOverrides {
        number,
        time,
        gas_limit,
        coinbase,
        random,
        base_fee,
        block_hash: _,
        difficulty: _,
    } = *block_overrides;
    if let Some(number) = number {
        block_env.number = number.saturating_to();
    }
    if let Some(time) = time {
        block_env.timestamp = U256::from(time);
    }
    if let Some(gas_limit) = gas_limit {
        block_env.gas_limit = U256::from(gas_limit);
    }
    if let Some(coinbase) = coinbase {
        block_env.coinbase = coinbase;
    }
    if let Some(random) = random {
        block_env.prevrandao = Some(random);
    }
    if let Some(base_fee) = base_fee {
        block_env.basefee = base_fee.saturating_to();
    }
}
