use core::str::FromStr;

use sov_modules_api::hooks::TxHooks;
use sov_modules_api::macros::config_constant;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{Context, WorkingSet};

use crate::{Bank, Coins};

#[config_constant]
// This constant is a fixed value, expected to be generated as
//
// ```rust
// let token_name = "sov-gas-token";
// let deployer = DEPLOYER;
// let salt = 0;
// let computed = super::get_token_address::<DefaultContext>(token_name, &deployer, salt);
// ```
//
// TODO: fetch address as constant
// https://github.com/Sovereign-Labs/sovereign-sdk/issues/1234
const GAS_TOKEN_ADDRESS: &'static str;

/// The computed addresses of a pre-dispatch tx hook.
pub struct BankTxHook<C: Context> {
    /// The tx sender address
    pub sender: C::Address,
}

impl<C: Context> TxHooks for Bank<C> {
    type Context = C;
    type PreArg = BankTxHook<C>;
    type PreResult = ();

    fn pre_dispatch_tx_hook(
        &self,
        _tx: &Transaction<C>,
        working_set: &mut WorkingSet<C>,
        hook: &BankTxHook<C>,
    ) -> anyhow::Result<()> {
        let BankTxHook { sender } = hook;
        let amount = 0;

        if amount > 0 {
            let token_address = C::Address::from_str(GAS_TOKEN_ADDRESS)
                .map_err(|_| anyhow::anyhow!("failed to parse gas token address"))?;
            let from = sender;
            let to = sender;
            let coins = Coins {
                amount,
                token_address,
            };
            self.transfer_from(from, to, coins, working_set)?;
        }

        Ok(())
    }

    fn post_dispatch_tx_hook(
        &self,
        _tx: &Transaction<Self::Context>,
        ctx: &C,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        let amount = 0;

        if amount > 0 {
            let token_address = C::Address::from_str(GAS_TOKEN_ADDRESS)
                .map_err(|_| anyhow::anyhow!("failed to parse gas token address"))?;
            let from = ctx.sender();
            let to = ctx.sender();
            let coins = Coins {
                amount,
                token_address,
            };
            self.transfer_from(from, to, coins, working_set)?;
        }

        Ok(())
    }
}
