use std::str::FromStr;

use reth_primitives::{Address, TxKind};
use revm::primitives::{CfgEnvWithHandlerCfg, ExecutionResult, Output, SpecId, KECCAK_EMPTY, U256};
use revm::{Database, DatabaseCommit};
use sov_modules_api::WorkingSet;
use sov_prover_storage_manager::new_orphan_storage;

use super::db::{DBError, EvmDb};
use super::db_init::InitEvmDb;
use super::executor;
use crate::evm::handler::CitreaExternal;
use crate::evm::primitive_types::BlockEnv;
use crate::evm::AccountInfo;
use crate::smart_contracts::SimpleStorageContract;
use crate::tests::test_signer::TestSigner;
use crate::Evm;

type C = sov_modules_api::default_context::DefaultContext;

use crate::tests::DEFAULT_CHAIN_ID;

#[test]
fn simple_contract_execution_sov_state() {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut working_set: WorkingSet<C> =
        WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());

    let evm = Evm::<C>::default();
    let evm_db: EvmDb<'_, C> = evm.get_db(&mut working_set);

    simple_contract_execution(evm_db);
}

fn simple_contract_execution<DB: Database<Error = DBError> + DatabaseCommit + InitEvmDb>(
    mut evm_db: DB,
) {
    let dev_signer = TestSigner::new_random();
    let caller = dev_signer.address();
    evm_db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: KECCAK_EMPTY,
            nonce: 1,
        },
    );

    let contract = SimpleStorageContract::default();

    // We are not supporting CANCUN yet
    // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
    let mut cfg_env = CfgEnvWithHandlerCfg::new_with_spec_id(Default::default(), SpecId::SHANGHAI);
    cfg_env.chain_id = DEFAULT_CHAIN_ID;

    let mut citrea_ext = CitreaExternal::new(0);

    let contract_address: Address = {
        let tx = dev_signer
            .sign_default_transaction(TxKind::Create, contract.byte_code(), 1, 0)
            .unwrap();

        let tx = &tx.try_into().unwrap();
        let block_env = BlockEnv {
            gas_limit: reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
            ..Default::default()
        };

        let result =
            executor::execute_tx(&mut evm_db, block_env, tx, cfg_env.clone(), &mut citrea_ext)
                .unwrap();
        contract_address(&result).expect("Expected successful contract creation")
    };

    let set_arg = 21989;

    {
        let call_data = contract.set_call_data(set_arg);

        let tx = dev_signer
            .sign_default_transaction(TxKind::Call(contract_address), call_data.clone(), 2, 0)
            .unwrap();
        let tx = &tx.try_into().unwrap();

        executor::execute_tx(
            &mut evm_db,
            BlockEnv::default(),
            tx,
            cfg_env.clone(),
            &mut citrea_ext,
        )
        .unwrap();
    }

    let get_res = {
        let call_data = contract.get_call_data();

        let tx = dev_signer
            .sign_default_transaction(TxKind::Call(contract_address), call_data.clone(), 3, 0)
            .unwrap();

        let tx = &tx.try_into().unwrap();

        let result = executor::execute_tx(
            &mut evm_db,
            BlockEnv::default(),
            tx,
            cfg_env.clone(),
            &mut citrea_ext,
        )
        .unwrap();

        let out = output(result);
        U256::from_be_slice(out.to_vec().as_slice())
    };

    assert_eq!(U256::from(set_arg), get_res);

    {
        let failing_call_data = contract.failing_function_call_data();

        let tx = dev_signer
            .sign_default_transaction(TxKind::Call(contract_address), failing_call_data, 4, 0)
            .unwrap();
        let tx = &tx.try_into().unwrap();

        let result = executor::execute_tx(
            &mut evm_db,
            BlockEnv::default(),
            tx,
            cfg_env.clone(),
            &mut citrea_ext,
        )
        .unwrap();

        assert!(matches!(result, ExecutionResult::Revert { .. }));
    }
}

fn contract_address(result: &ExecutionResult) -> Option<Address> {
    match result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(addr)),
            ..
        } => Some(*addr),
        _ => None,
    }
}

fn output(result: ExecutionResult) -> alloy_primitives::Bytes {
    match result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(out) => out,
            Output::Create(out, _) => out,
        },
        _ => panic!("Expected successful ExecutionResult"),
    }
}
