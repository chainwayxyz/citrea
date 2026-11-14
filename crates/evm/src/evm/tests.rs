use std::str::FromStr;

use alloy_eips::eip1559::ETHEREUM_BLOCK_GAS_LIMIT_30M;
use alloy_primitives::map::HashMap;
use alloy_primitives::{Address, TxKind, U256};
use reth_primitives::{Recovered, TransactionSigned};
use revm::context::result::{ExecutionResult, Output};
use revm::context::{BlockEnv, CfgEnv};
use revm::primitives::hardfork::SpecId;
use revm::state::{Account, EvmStorageSlot};
use revm::DatabaseCommit;
use sov_modules_api::{Spec, SpecId as CitreaSpecId, StateValueAccessor, WorkingSet};
use sov_prover_storage_manager::new_orphan_storage;

use self::executor::CitreaEvm;
use super::db::EvmDb;
use super::db_init::InitEvmDb;
use super::executor;
use crate::evm::handler::CitreaChain;
use crate::evm::AccountInfo;
use crate::smart_contracts::SimpleStorageContract;
use crate::tests::test_signer::TestSigner;
use crate::Evm;

type C = sov_modules_api::default_context::DefaultContext;

use crate::tests::DEFAULT_CHAIN_ID;

#[test]
fn simple_contract_execution_sov_state() {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut working_set = WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());

    let evm = Evm::<C>::default();
    let evm_db: EvmDb<'_, C> = evm.get_db(&mut working_set, CitreaSpecId::latest());

    simple_contract_execution(evm_db);
}

#[test]
fn db_commit_pre_sload_fix_persists_unchanged_storage_slots() {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut working_set = WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());

    let evm = Evm::<C>::default();
    let address = Address::from([0x44; 20]);
    let key = U256::from(0x1234);

    let mut account = Account::default();
    account.mark_touch();
    account.storage.insert(key, EvmStorageSlot::new(U256::ZERO));

    let mut changes = HashMap::default();
    changes.insert(address, account);

    {
        let mut evm_db: EvmDb<'_, C> =
            EvmDb::new(&evm, &mut working_set, CitreaSpecId::TangeloSelfdestructFix);
        evm_db.commit(changes);
    }

    assert_eq!(
        evm.storage_get(&address, &key, &mut working_set),
        Some(U256::ZERO)
    );
}

#[test]
fn db_commit_sload_fix_skips_unchanged_storage_slots() {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut working_set: WorkingSet<<C as Spec>::Storage> =
        WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());

    let evm = Evm::<C>::default();
    let address = Address::from([0x45; 20]);
    let unchanged_key = U256::from(0x1234);
    let changed_key = U256::from(0x5678);
    let changed_value = U256::from(0x09);

    let mut account = Account::default();
    account.mark_touch();
    account
        .storage
        .insert(unchanged_key, EvmStorageSlot::new(U256::ZERO));
    account.storage.insert(
        changed_key,
        EvmStorageSlot::new_changed(U256::ZERO, changed_value),
    );

    let mut changes = HashMap::default();
    changes.insert(address, account);

    {
        let mut evm_db: EvmDb<'_, C> = EvmDb::new(&evm, &mut working_set, CitreaSpecId::Pomelo);
        evm_db.commit(changes);
    }

    assert_eq!(
        evm.storage_get(&address, &unchanged_key, &mut working_set),
        None
    );
    assert_eq!(
        evm.storage_get(&address, &changed_key, &mut working_set),
        Some(changed_value)
    );
}

#[test]
fn db_commit_pomelo_selfdestruct_does_not_allocate_an_empty_account() {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut working_set: WorkingSet<<C as Spec>::Storage> =
        WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());

    let evm = Evm::<C>::default();
    let address = Address::from([0x46; 20]);

    let mut account = Account::new_not_existing();
    account.mark_touch();
    account.mark_selfdestruct();

    let mut changes = HashMap::default();
    changes.insert(address, account);

    {
        let mut evm_db: EvmDb<'_, C> = EvmDb::new(&evm, &mut working_set, CitreaSpecId::Pomelo);
        evm_db.commit(changes);
    }

    assert!(!evm.account_exists(&address, &mut working_set));
    assert_eq!(evm.account_info(&address, &mut working_set), None);
    assert_eq!(
        evm.account_amount.get(&mut working_set).unwrap_or_default(),
        0,
        "a same-transaction SELFDESTRUCT must not allocate an account index"
    );
}

#[test]
fn db_commit_pre_pomelo_selfdestruct_preserves_legacy_empty_account() {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut working_set: WorkingSet<<C as Spec>::Storage> =
        WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());

    let evm = Evm::<C>::default();
    let address = Address::from([0x47; 20]);

    let mut account = Account::new_not_existing();
    account.mark_touch();
    account.mark_selfdestruct();

    let mut changes = HashMap::default();
    changes.insert(address, account);

    {
        let mut evm_db: EvmDb<'_, C> =
            EvmDb::new(&evm, &mut working_set, CitreaSpecId::TangeloSelfdestructFix);
        evm_db.commit(changes);
    }

    assert_eq!(
        evm.account_info(&address, &mut working_set),
        Some(AccountInfo::default())
    );
    assert_eq!(
        evm.account_amount.get(&mut working_set).unwrap_or_default(),
        1,
        "the historical SELFDESTRUCT path must retain its allocated account index"
    );
}

fn simple_contract_execution<C: sov_modules_api::Context>(mut evm_db: EvmDb<C>) {
    let dev_signer = TestSigner::new_default();
    let caller = dev_signer.address();
    evm_db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: None,
            nonce: 1,
        },
    );

    let contract = SimpleStorageContract::default();

    let mut cfg_env = CfgEnv::new_with_spec(SpecId::CANCUN);
    cfg_env.chain_id = DEFAULT_CHAIN_ID;

    let mut citrea_ext = CitreaChain::new(0);

    let contract_address: Address = {
        let tx = dev_signer
            .sign_default_transaction(TxKind::Create, contract.byte_code(), 1, 0)
            .unwrap();

        let tx = &tx.try_into().unwrap();
        let block_env = BlockEnv {
            gas_limit: ETHEREUM_BLOCK_GAS_LIMIT_30M,
            ..Default::default()
        };

        let result = execute_tx(&mut evm_db, block_env, tx, cfg_env.clone(), &mut citrea_ext);
        contract_address(&result).expect("Expected successful contract creation")
    };

    let set_arg = 21989;

    {
        let call_data = contract.set_call_data(set_arg);

        let tx = dev_signer
            .sign_default_transaction(TxKind::Call(contract_address), call_data.clone(), 2, 0)
            .unwrap();
        let tx = &tx.try_into().unwrap();

        execute_tx(
            &mut evm_db,
            BlockEnv::default(),
            tx,
            cfg_env.clone(),
            &mut citrea_ext,
        );
    }

    let get_res = {
        let call_data = contract.get_call_data();

        let tx = dev_signer
            .sign_default_transaction(TxKind::Call(contract_address), call_data.clone(), 3, 0)
            .unwrap();

        let tx = &tx.try_into().unwrap();

        let result = execute_tx(
            &mut evm_db,
            BlockEnv::default(),
            tx,
            cfg_env.clone(),
            &mut citrea_ext,
        );

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

        let result = execute_tx(
            &mut evm_db,
            BlockEnv::default(),
            tx,
            cfg_env.clone(),
            &mut citrea_ext,
        );

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

pub(crate) fn execute_tx<C: sov_modules_api::Context>(
    db: &mut EvmDb<C>,
    block_env: BlockEnv,
    tx: &Recovered<TransactionSigned>,
    config_env: CfgEnv,
    ext: &mut CitreaChain,
) -> ExecutionResult {
    let mut evm = CitreaEvm::new(db, block_env, config_env, ext);
    let res = evm.transact(tx).unwrap();
    evm.commit(res.state);

    res.result
}

/// Contract code is committed to state only as `keccak256(runtime bytes)`, so everything
/// else a stored value carries -- jump table, padding, `original_len`, an EIP-7702
/// delegation target -- is unauthenticated and must be checked against those bytes.
///
/// The check runs where an unverified value can first enter: a read that reaches storage.
/// The `read_back` tests therefore commit and reopen the working set, because a value
/// written and read back on one working set is served from the offchain cache and checked
/// nothing. The `db_commit` tests cover the other half: that nothing on the commit path
/// puts an unverified value into that cache to begin with.
mod bytecode_canonicalization {
    use std::str::FromStr;
    use std::sync::Arc;

    use alloy_primitives::map::HashMap;
    use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
    use revm::bytecode::eip7702::Eip7702Bytecode;
    use revm::bytecode::eof::Eof;
    use revm::bytecode::opcode::{JUMPDEST, POP, PUSH1, STOP};
    use revm::bytecode::JumpTable;
    use revm::state::{Account, AccountInfo, Bytecode};
    use revm::{Database, DatabaseCommit};
    use sov_modules_api::default_context::ZkDefaultContext;
    use sov_modules_api::{SpecId as CitreaSpecId, WorkingSet};
    use sov_prover_storage_manager::new_orphan_storage;
    use sov_state::{Witness, ZkStorage};

    use super::C;
    use crate::evm::db::{DBError, EvmDb};
    use crate::evm::db_init::InitEvmDb;
    use crate::smart_contracts::SimpleStorageContract;
    use crate::tests::utils::{commit, config_push_contracts};
    use crate::{Evm, EvmConfig};

    /// `PUSH1 0x5B; POP; JUMPDEST; STOP`
    ///
    /// The `0x5B` at index 1 is the PUSH's immediate, not an instruction; the one
    /// at index 3 is the only genuine jump destination. Telling the two apart is
    /// the entire job of jump analysis.
    const RUNTIME: [u8; 5] = [PUSH1, JUMPDEST, POP, JUMPDEST, STOP];

    /// Stores `stored` under `code_hash` the way genesis does, commits it, then reads it
    /// back on a fresh working set -- so the read misses the cache and reaches storage,
    /// which is the only place the verification runs.
    fn read_back(code_hash: B256, stored: Bytecode) -> Result<Bytecode, DBError> {
        let tmpdir = tempfile::tempdir().unwrap();
        let storage = new_orphan_storage(tmpdir.path()).unwrap();
        let evm = Evm::<C>::default();

        let mut working_set = WorkingSet::new(storage.clone());
        evm.get_db(&mut working_set, CitreaSpecId::latest())
            .insert_code(code_hash, stored);
        commit(working_set, storage.clone());

        let mut working_set = WorkingSet::new(storage);
        let mut db: EvmDb<'_, C> = evm.get_db(&mut working_set, CitreaSpecId::latest());
        db.code_by_hash(code_hash)
    }

    #[test]
    fn code_by_hash_returns_honest_bytecode_unchanged() {
        for runtime in [
            Bytes::from_static(&RUNTIME),
            Bytes::from(SimpleStorageContract::default().byte_code()),
            Bytecode::new_eip7702(Address::from([0x11; 20])).original_bytes(),
        ] {
            // What genesis (`Bytecode::new_raw`) and REVM's own deploy-time
            // analysis both produce. Re-deriving must reproduce it bit for bit,
            // or this would change historical execution and need a fork gate.
            let honest = Bytecode::new_raw(runtime.clone());

            assert_eq!(read_back(keccak256(&runtime), honest.clone()), Ok(honest));
        }
    }

    #[test]
    fn code_by_hash_rejects_a_forged_jump_table() {
        let runtime = Bytes::from_static(&RUNTIME);
        let code_hash = keccak256(&runtime);
        let honest = Bytecode::new_raw(runtime.clone());

        let Bytecode::LegacyAnalyzed(analyzed) = &honest else {
            panic!("legacy bytecode expected");
        };
        let padded = analyzed.bytecode().clone();

        // Marks the PUSH data at index 1 valid and the real JUMPDEST at index 3
        // invalid -- the exact inverse of honest analysis. Bit `pc` of an `Lsb0`
        // bitvec is bit `pc % 8` of byte `pc / 8`.
        let forged_table = JumpTable::from_slice(&[0b0000_0010, 0, 0, 0, 0], padded.len());
        let forged = Bytecode::new_analyzed(padded, runtime.len(), forged_table);

        // A well-formed value whose bytes hash correctly, so it survives any
        // check made against the code hash alone.
        assert_eq!(forged.hash_slow(), code_hash);

        // The honest analysis disagrees, which is what the check catches: it never
        // becomes the jump table the interpreter runs against.
        let honest_table = honest.legacy_jump_table().unwrap();
        assert!(honest_table.is_valid(3), "the real JUMPDEST is reachable");
        assert!(
            !honest_table.is_valid(1),
            "PUSH data is not a jump destination"
        );

        assert_eq!(
            read_back(code_hash, forged),
            Err(DBError::MalformedCode),
            "a jump table that is not the one the code implies must be rejected"
        );
    }

    #[test]
    fn code_by_hash_rejects_an_eip7702_wrapper_around_contract_code() {
        let runtime = Bytes::from(SimpleStorageContract::default().byte_code());
        let code_hash = keccak256(&runtime);

        // `Eip7702Bytecode`'s fields are public and its `Deserialize` derive
        // bypasses `new_raw`, so nothing forces `raw` to be a 23-byte designator.
        // `original_byte_slice()` returns `raw` for this variant, so the value
        // hashes to the genuine contract while delegating every call away from it.
        let forged = Bytecode::Eip7702(Eip7702Bytecode {
            delegated_address: Address::from([0xaa; 20]),
            version: 0,
            raw: runtime.clone(),
        });
        assert_eq!(forged.hash_slow(), code_hash);

        assert_eq!(
            read_back(code_hash, forged),
            Err(DBError::MalformedCode),
            "these bytes are legacy code, not a delegation"
        );
    }

    #[test]
    fn code_by_hash_rejects_a_forged_eip7702_delegation_target() {
        let genuine = Address::from([0x11; 20]);
        let designator = Bytecode::new_eip7702(genuine);
        let raw = designator.original_bytes();

        // A genuine 23-byte designator whose cached `delegated_address` disagrees
        // with the bytes it is derived from.
        let forged = Bytecode::Eip7702(Eip7702Bytecode {
            delegated_address: Address::from([0xaa; 20]),
            version: 0,
            raw,
        });

        let code_hash = designator.hash_slow();
        assert_eq!(forged.hash_slow(), code_hash);

        assert_eq!(
            read_back(code_hash, forged),
            Err(DBError::MalformedCode),
            "the delegation target must be the one the designator bytes encode"
        );
    }

    #[test]
    fn code_by_hash_rejects_code_that_is_not_the_preimage_of_its_key() {
        let unrelated = Bytecode::new_raw(Bytes::from_static(&[STOP]));

        assert_eq!(
            read_back(keccak256(RUNTIME), unrelated),
            Err(DBError::CodeHashMismatch)
        );
    }

    /// Builds a `LegacyAnalyzed` whose `original_len` runs past its own buffer.
    ///
    /// `LegacyAnalyzedBytecode::new` panics on that, so such a value can only be
    /// built the way the offchain map builds one: by decoding it. BCS writes
    /// `usize` as a little-endian `u64`, so the field is located by diffing two
    /// encodings that differ only there.
    fn with_forged_original_len(honest: &Bytecode, forged_len: u8) -> Bytecode {
        let Bytecode::LegacyAnalyzed(analyzed) = honest else {
            panic!("legacy bytecode expected");
        };
        let padded = analyzed.bytecode().clone();
        let jump_table = analyzed.jump_table().clone();

        let one = bcs::to_bytes(&Bytecode::new_analyzed(
            padded.clone(),
            1,
            jump_table.clone(),
        ))
        .unwrap();
        let mut two = bcs::to_bytes(&Bytecode::new_analyzed(padded, 2, jump_table)).unwrap();

        let offset = one
            .iter()
            .zip(&two)
            .position(|(a, b)| a != b)
            .expect("original_len must be encoded");
        two[offset] = forged_len;

        bcs::from_bytes(&two).expect("a forged length is still well-formed BCS")
    }

    #[test]
    fn code_by_hash_rejects_an_original_len_past_its_buffer() {
        let runtime = Bytes::from_static(&RUNTIME);
        let honest = Bytecode::new_raw(runtime.clone());

        // `original_byte_slice()` indexes straight into the buffer, so reading
        // this value's bytes at all would panic rather than return an error.
        let forged = with_forged_original_len(&honest, 200);

        assert_eq!(
            read_back(keccak256(&runtime), forged),
            Err(DBError::MalformedCode)
        );
    }

    /// The forged value from `code_by_hash_rejects_a_forged_jump_table`, alongside the
    /// honest one it collides with: same bytes and therefore the same hash, with the two
    /// meaningful jump-table bits inverted.
    fn honest_and_forged() -> (B256, Bytecode, Bytecode) {
        let runtime = Bytes::from_static(&RUNTIME);
        let code_hash = keccak256(&runtime);
        let honest = Bytecode::new_raw(runtime.clone());

        let Bytecode::LegacyAnalyzed(analyzed) = &honest else {
            panic!("legacy bytecode expected");
        };
        let padded = analyzed.bytecode().clone();
        let forged_table = JumpTable::from_slice(&[0b0000_0010, 0, 0, 0, 0], padded.len());
        let forged = Bytecode::new_analyzed(padded, runtime.len(), forged_table);
        assert_eq!(forged.hash_slow(), code_hash);

        (code_hash, honest, forged)
    }

    /// A deployment of `code` at `address`, shaped the way revm hands it to
    /// `DatabaseCommit::commit`.
    fn deployment(address: Address, code_hash: B256, code: &Bytecode) -> HashMap<Address, Account> {
        let mut account = Account {
            info: AccountInfo {
                balance: U256::ZERO,
                nonce: 1,
                code_hash,
                code: Some(code.clone()),
            },
            ..Default::default()
        };
        account.mark_created();
        account.mark_touch();

        let mut changes = HashMap::default();
        changes.insert(address, account);
        changes
    }

    /// Regression test. `verify_code` only runs on a read that *misses* the offchain
    /// cache, so nothing may put an unverified value into that cache first. `db_commit`
    /// used to: it probed `offchain_code` for presence before writing newly deployed
    /// code, and in the circuit that probe's answer is a raw witness hint
    /// (`ZkStorage::get_offchain` ignores the key), i.e. fully prover-chosen. The cached
    /// hint then served the later `code_by_hash`, which saw a cache hit and verified
    /// nothing -- so the forged value below came back as `Ok`.
    ///
    /// Seeding native storage with it stands in for that hint.
    #[test]
    fn db_commit_does_not_seed_the_offchain_cache_with_unverified_code() {
        let (code_hash, honest, forged) = honest_and_forged();

        let tmpdir = tempfile::tempdir().unwrap();
        let storage = new_orphan_storage(tmpdir.path()).unwrap();
        let evm = Evm::<C>::default();

        let mut working_set = WorkingSet::new(storage.clone());
        evm.get_db(&mut working_set, CitreaSpecId::latest())
            .insert_code(code_hash, forged);
        commit(working_set, storage.clone());

        // Deploy, then read the code back on the same working set -- what a block that
        // deploys a contract and then calls it produces.
        let mut working_set = WorkingSet::new(storage);
        let mut db: EvmDb<'_, C> = evm.get_db(&mut working_set, CitreaSpecId::latest());
        db.commit(deployment(Address::from([0x42; 20]), code_hash, &honest));

        assert_eq!(db.code_by_hash(code_hash), Ok(honest));
    }

    /// The write condition is "this account did not already have this code", compared
    /// against the JMT, rather than "this code is not stored yet", which needed the
    /// offchain read. Both changed cases have to keep resolving: a second account
    /// deploying identical code rewrites the entry with revm's own canonical value, and
    /// an account whose code hash is unchanged writes nothing.
    #[test]
    fn db_commit_stores_code_per_account_not_per_code_hash() {
        let runtime = Bytes::from(SimpleStorageContract::default().byte_code());
        let code_hash = keccak256(&runtime);
        let honest = Bytecode::new_raw(runtime);

        let tmpdir = tempfile::tempdir().unwrap();
        let storage = new_orphan_storage(tmpdir.path()).unwrap();
        let evm = Evm::<C>::default();

        let first = Address::from([0x11; 20]);
        let second = Address::from([0x22; 20]);

        for address in [first, second] {
            let mut working_set = WorkingSet::new(storage.clone());
            evm.get_db(&mut working_set, CitreaSpecId::latest())
                .commit(deployment(address, code_hash, &honest));
            commit(working_set, storage.clone());
        }

        // Touching `first` again leaves the stored entry alone, so this read reaches
        // storage and goes through `verify_code`.
        let mut working_set = WorkingSet::new(storage);
        let mut db: EvmDb<'_, C> = evm.get_db(&mut working_set, CitreaSpecId::latest());
        db.commit(deployment(first, code_hash, &honest));

        assert_eq!(db.code_by_hash(code_hash), Ok(honest));
    }

    /// Records `stored` in an offchain witness, then resolves it through `ZkStorage`.
    fn read_back_zk(code_hash: B256, stored: Bytecode) -> Result<Bytecode, DBError> {
        let tmpdir = tempfile::tempdir().unwrap();
        let storage = new_orphan_storage(tmpdir.path()).unwrap();
        let evm = Evm::<C>::default();

        let mut working_set = WorkingSet::new(storage.clone());
        evm.get_db(&mut working_set, CitreaSpecId::latest())
            .insert_code(code_hash, stored);
        commit(working_set, storage.clone());

        // The storage value is added to the witness before `code_by_hash` validates it.
        let mut working_set = WorkingSet::new(storage);
        let _ = evm
            .get_db(&mut working_set, CitreaSpecId::latest())
            .code_by_hash(code_hash);
        let offchain_witness = working_set.checkpoint().freeze_offchain().1;

        let evm_zk = Evm::<ZkDefaultContext>::default();
        let mut zk_working_set =
            WorkingSet::with_witness(ZkStorage::new(), Witness::default(), offchain_witness);
        evm_zk
            .get_db(&mut zk_working_set, CitreaSpecId::latest())
            .code_by_hash(code_hash)
    }

    #[test]
    fn circuit_reads_honest_code_from_the_witness_hint() {
        let runtime = Bytes::from_static(&RUNTIME);
        let honest = Bytecode::new_raw(runtime.clone());

        assert_eq!(
            read_back_zk(keccak256(&runtime), honest.clone()),
            Ok(honest)
        );
    }

    #[test]
    fn circuit_rejects_a_forged_jump_table_from_the_witness() {
        let (code_hash, _, forged) = honest_and_forged();

        assert_eq!(read_back_zk(code_hash, forged), Err(DBError::MalformedCode));
    }

    /// A canonical deployment must repair a forged value persisted by an earlier commit.
    #[test]
    fn an_honest_deploy_repairs_a_persisted_forgery() {
        let (code_hash, honest, forged) = honest_and_forged();

        let tmpdir = tempfile::tempdir().unwrap();
        let storage = new_orphan_storage(tmpdir.path()).unwrap();
        let evm = Evm::<C>::default();

        let mut working_set = WorkingSet::new(storage.clone());
        evm.get_db(&mut working_set, CitreaSpecId::latest())
            .insert_code(code_hash, forged);
        commit(working_set, storage.clone());

        let mut working_set = WorkingSet::new(storage.clone());
        evm.get_db(&mut working_set, CitreaSpecId::latest())
            .commit(deployment(Address::from([0x42; 20]), code_hash, &honest));
        commit(working_set, storage.clone());

        let mut working_set = WorkingSet::new(storage);
        let mut db: EvmDb<'_, C> = evm.get_db(&mut working_set, CitreaSpecId::latest());
        assert_eq!(db.code_by_hash(code_hash), Ok(honest));
    }

    /// Applies the forged jump-table primitive to the Bridge implementation in genesis.
    #[test]
    fn code_by_hash_rejects_a_zeroed_jump_table_on_the_real_bridge_bytecode() {
        let mut config = EvmConfig::default();
        config_push_contracts(&mut config, None);

        let bridge = Address::from_str("0x3200000000000000000000000000000000000002").unwrap();
        let runtime = config
            .data
            .into_iter()
            .find(|account| account.address == bridge)
            .expect("the Bridge is a genesis account")
            .code;

        let code_hash = keccak256(&runtime);
        let honest = Bytecode::new_raw(runtime);

        let Bytecode::LegacyAnalyzed(analyzed) = &honest else {
            panic!("legacy bytecode expected");
        };
        let padded = analyzed.bytecode().clone();
        let honest_table = analyzed.jump_table().clone();

        let zeroed = JumpTable::from_slice(&vec![0u8; padded.len().div_ceil(8)], padded.len());
        let forged = Bytecode::new_analyzed(padded, honest.original_byte_slice().len(), zeroed);
        assert_eq!(forged.hash_slow(), code_hash);
        assert_ne!(
            honest_table,
            *forged.legacy_jump_table().unwrap(),
            "the forged table differs from the Bridge's real analysis"
        );

        assert_eq!(
            read_back(code_hash, forged),
            Err(DBError::MalformedCode),
            "a Bridge with its jump destinations stripped must be rejected"
        );
    }

    /// Ordinary legacy bytes cannot be accepted with forged EOF metadata.
    #[test]
    fn code_by_hash_rejects_an_eof_wrapper_around_contract_code() {
        let runtime = Bytes::from(SimpleStorageContract::default().byte_code());
        let code_hash = keccak256(&runtime);

        let forged = Bytecode::Eof(Arc::new(Eof {
            raw: runtime.clone(),
            ..Default::default()
        }));
        assert_eq!(forged.hash_slow(), code_hash);

        assert_eq!(
            read_back(code_hash, forged),
            Err(DBError::MalformedCode),
            "these bytes are legacy code, not an EOF container"
        );
    }
}
