//! Citrea-specific mempool admission validator.
//!
//! Reth's stock [`EthTransactionValidator`] only checks that the sender can cover the L2 cost
//! (`max_fee_per_gas * gas_limit + value`). Citrea additionally charges an L1 data-availability
//! fee during execution, which reth's validator has no knowledge of, so on its own it can admit a
//! transaction whose sender cannot cover that L1 fee.
//!
//! [`CitreaTransactionValidator`] extends admission to account for it: after the stock checks
//! pass, it simulates the transaction to price its L1 fee and only admits it when the sender can
//! also cover that fee (`balance >= cost() + l1_fee`). This is a best-effort check against current
//! state and the latest fee rate; the exact L1 fee is only known at execution time, so it is not a
//! guarantee.

use citrea_primitives::forks::fork_from_block_number;
use reth_primitives_traits::Block;
use reth_transaction_pool::error::InvalidPoolTransactionError;
use reth_transaction_pool::{
    EthPooledTransaction, EthTransactionValidator, PoolTransaction, TransactionOrigin,
    TransactionValidationOutcome, TransactionValidator,
};
use sov_modules_api::WorkingSet;

use crate::db_provider::DbProvider;

/// Wraps reth's [`EthTransactionValidator`] and additionally reserves the Citrea L1 fee.
#[derive(Debug, Clone)]
pub(crate) struct CitreaTransactionValidator {
    /// Stock reth validator; runs first and provides all static + L2-balance checks.
    inner: EthTransactionValidator<DbProvider, EthPooledTransaction>,
    /// Handle to Citrea EVM state, used to simulate the tx and price its L1 fee.
    provider: DbProvider,
}

impl CitreaTransactionValidator {
    pub(crate) fn new(
        inner: EthTransactionValidator<DbProvider, EthPooledTransaction>,
        provider: DbProvider,
    ) -> Self {
        Self { inner, provider }
    }
}

impl TransactionValidator for CitreaTransactionValidator {
    type Transaction = EthPooledTransaction;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        // Stock validation first. This is the only `.await`; everything below is synchronous
        // CPU work, so no non-`Send` revm value ever crosses an await point.
        let outcome = self.inner.validate_transaction(origin, transaction).await;

        // Only transactions reth deems valid proceed to the L1-fee reservation. Invalid/Error
        // outcomes pass straight through.
        let TransactionValidationOutcome::Valid {
            balance,
            state_nonce,
            transaction,
            propagate,
        } = outcome
        else {
            return outcome;
        };

        // reth's reserved L2 cost already includes `value` (`max_fee_per_gas*gas_limit + value`),
        // and reth has guaranteed `balance >= cost()`. Simulate to price the extra L1 fee.
        // Borrows of `transaction` are confined to this block so it can be moved afterwards.
        let reth_cost = *transaction.transaction().cost();
        let sim = {
            let recovered = transaction.transaction().transaction();
            let mut working_set = WorkingSet::new(self.provider.storage.clone());
            self.provider.evm.simulate_tx_l1_fee(
                recovered,
                &mut working_set,
                fork_from_block_number,
            )
        };

        match sim {
            Ok(expenses) => {
                let required = reth_cost.saturating_add(expenses.l1_fee());
                if balance < required {
                    return TransactionValidationOutcome::Invalid(
                        transaction.into_transaction(),
                        InvalidPoolTransactionError::Overdraft {
                            cost: required,
                            balance,
                        },
                    );
                }
            }
            // A simulation failure must not block admission: reverting or halting transactions
            // are still priced (the handler runs to completion), so an error here reflects a
            // pre-execution problem rather than insufficient funds. Admit and let normal
            // execution handle it.
            Err(err) => {
                tracing::debug!(
                    target: "citrea::mempool",
                    ?err,
                    "L1 fee simulation failed during admission; admitting tx",
                );
            }
        }

        TransactionValidationOutcome::Valid {
            balance,
            state_nonce,
            transaction,
            propagate,
        }
    }

    fn on_new_head_block<B>(&self, new_tip_block: &reth_primitives_traits::SealedBlock<B>)
    where
        B: Block,
    {
        // Forward so the inner validator's fork tracker keeps advancing. The default trait impl
        // is a no-op, so skipping this would silently freeze fork-specific timestamp tracking.
        self.inner.on_new_head_block(new_tip_block);
    }
}
