use alloy_primitives::map::HashMap;
use alloy_primitives::{Address, U256};
use revm::state::Account;
use revm::DatabaseCommit;
use sov_rollup_interface::spec::SpecId;

use super::utils::get_evm;
use crate::evm::db::EvmDb;
use crate::evm::AccountInfo as DbAccountInfo;
use crate::tests::utils::get_evm_test_config;

#[test]
fn touched_empty_accounts_are_not_persisted() {
    let config = get_evm_test_config();
    let (evm, mut working_set, _spec_id, _ledger_db) = get_evm(&config);

    let mut evm_db = EvmDb::new(&evm, &mut working_set, SpecId::latest());

    let addresses = [
        Address::from([0x11; 20]),
        Address::from([0x12; 20]),
        Address::from([0x13; 20]),
        Address::from([0x14; 20]),
        Address::from([0x15; 20]),
        Address::from([0x16; 20]),
        Address::from([0x17; 20]),
        Address::from([0x18; 20]),
        Address::from([0x19; 20]),
        Address::from([0x1a; 20]),
    ];

    let mut changes: HashMap<Address, Account> = HashMap::default();
    for address in addresses {
        let mut account = Account::new_not_existing();
        account.mark_touch();
        changes.insert(address, account);
    }

    evm_db.commit(changes);

    for address in addresses {
        // EIP-161: touched-but-empty accounts must not be persisted.
        // Specification:
        // c. No account may change state from non-existent to existent-but-_empty_. If an operation would do this, the account SHALL instead remain non-existent.
        assert!(!evm.account_exists(&address, &mut working_set));
    }
}

/// Before Pomelo the legacy behaviour must be preserved: a touched, brand new empty
/// account is still written to state.
#[test]
fn pre_pomelo_touched_empty_accounts_are_persisted() {
    let config = get_evm_test_config();
    let (evm, mut working_set, _spec_id, _ledger_db) = get_evm(&config);

    let mut evm_db = EvmDb::new(&evm, &mut working_set, SpecId::TangeloSelfdestructFix);

    let address = Address::from([0x21; 20]);
    let mut account = Account::new_not_existing();
    account.mark_touch();

    let mut changes: HashMap<Address, Account> = HashMap::default();
    changes.insert(address, account);
    evm_db.commit(changes);

    assert!(
        evm.account_exists(&address, &mut working_set),
        "pre-Pomelo state clearing must stay disabled"
    );
}

#[test]
fn pre_pomelo_existing_account_emptied_is_still_written() {
    let config = get_evm_test_config();
    let (evm, mut working_set, _spec_id, _ledger_db) = get_evm(&config);

    let address = Address::from([0x22; 20]);
    evm.account_set(
        &address,
        &DbAccountInfo {
            balance: U256::from(100),
            nonce: 0,
            code_hash: None,
        },
        &mut working_set,
    );

    // An existing account that ends the transaction empty.
    let mut account = Account::default();
    account.mark_touch();

    let mut changes: HashMap<Address, Account> = HashMap::default();
    changes.insert(address, account);
    EvmDb::new(&evm, &mut working_set, SpecId::TangeloSelfdestructFix).commit(changes);

    assert_eq!(
        evm.account_info(&address, &mut working_set)
            .expect("account was written before the commit")
            .balance,
        U256::ZERO,
        "pre-Pomelo the emptied account info must still be written to state"
    );
}

/// Regression test for an existing account that ends up empty at Pomelo being
/// neither written nor deleted, leaving its previous, now stale, info in state.
///
/// Since account deletion is not supported, the existing index is retained and
/// its account info must be updated to empty so the EVM and stored state agree.
#[test]
fn pomelo_existing_account_emptied_does_not_keep_stale_info() {
    let config = get_evm_test_config();
    let (evm, mut working_set, _spec_id, _ledger_db) = get_evm(&config);

    let address = Address::from([0x23; 20]);
    evm.account_set(
        &address,
        &DbAccountInfo {
            balance: U256::from(100),
            nonce: 0,
            code_hash: None,
        },
        &mut working_set,
    );

    let mut account = Account::default();
    account.mark_touch();

    let mut changes: HashMap<Address, Account> = HashMap::default();
    changes.insert(address, account);
    EvmDb::new(&evm, &mut working_set, SpecId::Pomelo).commit(changes);

    assert_eq!(
        evm.account_info(&address, &mut working_set),
        Some(DbAccountInfo::default()),
        "the existing account must be written empty without deleting its index"
    );
}
