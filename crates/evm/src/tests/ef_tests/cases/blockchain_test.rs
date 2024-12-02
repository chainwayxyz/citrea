//! Test runners for `BlockchainTests` in <https://github.com/ethereum/tests>

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use alloy_primitives::B256;
use alloy_rlp::{Decodable, Encodable};
use rayon::iter::{ParallelBridge, ParallelIterator};
use reth_primitives::{SealedBlock, EMPTY_OMMER_ROOT_HASH};
use revm::primitives::SpecId;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, StateMapAccessor, StateValueAccessor, WorkingSet};
use sov_prover_storage_manager::SnapshotManager;
use sov_rollup_interface::spec::SpecId as SovSpecId;
use sov_state::ProverStorage;

use crate::evm::DbAccount;
use crate::primitive_types::Block;
use crate::tests::ef_tests::models::{BlockchainTest, ForkSpec};
use crate::tests::ef_tests::{Case, Error, Suite};
use crate::tests::utils::{commit, config_push_contracts, get_evm_with_storage};
use crate::{AccountData, Evm, EvmChainConfig, EvmConfig, RlpEvmTransaction, U256};

/// A handler for the blockchain test suite.
#[derive(Debug)]
pub struct BlockchainTests {
    suite: String,
}

impl BlockchainTests {
    /// Create a new handler for a subset of the blockchain test suite.
    pub fn new(suite: String) -> Self {
        Self { suite }
    }
}

impl Suite for BlockchainTests {
    type Case = BlockchainTestCase;

    fn suite_name(&self) -> String {
        format!("BlockchainTests/{}", self.suite)
    }
}

/// An Ethereum blockchain test.
#[derive(Debug, PartialEq, Eq)]
pub struct BlockchainTestCase {
    tests: BTreeMap<String, BlockchainTest>,
    skip: bool,
}

impl BlockchainTestCase {
    fn execute_transactions(
        &self,
        evm: &mut Evm<DefaultContext>,
        txs: Vec<RlpEvmTransaction>,
        mut working_set: WorkingSet<DefaultContext>,
        storage: ProverStorage<SnapshotManager>,
        root: &[u8; 32],
        l2_height: u64,
    ) -> (WorkingSet<DefaultContext>, ProverStorage<SnapshotManager>) {
        let l1_fee_rate = 0;
        // Call begin_soft_confirmation_hook
        let soft_confirmation_info = HookSoftConfirmationInfo {
            l2_height,
            da_slot_hash: [0u8; 32],
            da_slot_height: 0,
            da_slot_txs_commitment: [0u8; 32],
            pre_state_root: root.to_vec(),
            current_spec: SovSpecId::Genesis,
            pub_key: vec![],
            deposit_data: vec![],
            l1_fee_rate,
            timestamp: 0,
        };
        evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

        let dummy_address = generate_address::<DefaultContext>("dummy");
        let context =
            DefaultContext::new(dummy_address, l2_height, SovSpecId::Genesis, l1_fee_rate);
        let _ = evm.execute_call(txs, &context, &mut working_set);

        evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
        let root = commit(working_set, storage.clone());
        let mut working_set: WorkingSet<DefaultContext> = WorkingSet::new(storage.clone());
        evm.finalize_hook(&root.into(), &mut working_set.accessory_state());

        (working_set, storage)
    }
}

impl Case for BlockchainTestCase {
    fn load(path: &Path) -> Result<Self, Error> {
        Ok(BlockchainTestCase {
            tests: {
                let s = fs::read_to_string(path).map_err(|error| Error::Io {
                    path: path.into(),
                    error,
                })?;
                serde_json::from_str(&s).map_err(|error| Error::CouldNotDeserialize {
                    path: path.into(),
                    error,
                })?
            },
            skip: should_skip(path),
        })
    }

    /// Runs the test cases for the Ethereum Forks test suite.
    ///
    /// # Errors
    /// Returns an error if the test is flagged for skipping or encounters issues during execution.
    fn run(&self) -> Result<(), Error> {
        // If the test is marked for skipping, return a Skipped error immediately.
        if self.skip {
            return Err(Error::Skipped);
        }

        // Iterate through test cases, filtering by the network type to exclude specific forks.
        self.tests
            .values()
            .filter(|case| matches!(case.network, ForkSpec::Shanghai))
            .par_bridge()
            .try_for_each(|case| {
                let mut evm_config = EvmConfig::default();
                config_push_contracts(&mut evm_config, None);
                // Set this base fee based on what's set in genesis.
                let header = reth_primitives::Header {
                    parent_hash: case.genesis_block_header.parent_hash,
                    ommers_hash: EMPTY_OMMER_ROOT_HASH,
                    beneficiary: evm_config.coinbase,
                    // This will be set in finalize_hook or in the next begin_slot_hook
                    state_root: case.genesis_block_header.state_root,
                    transactions_root: case.genesis_block_header.transactions_trie,
                    receipts_root: case.genesis_block_header.receipt_trie,
                    withdrawals_root: case.genesis_block_header.withdrawals_root,
                    logs_bloom: case.genesis_block_header.bloom,
                    difficulty: case.genesis_block_header.difficulty,
                    number: case.genesis_block_header.number.to(),
                    gas_limit: case.genesis_block_header.gas_limit.to(),
                    gas_used: case.genesis_block_header.gas_used.to(),
                    timestamp: case.genesis_block_header.timestamp.to(),
                    mix_hash: case.genesis_block_header.mix_hash,
                    nonce: case.genesis_block_header.nonce.into(),
                    base_fee_per_gas: case.genesis_block_header.base_fee_per_gas.map(|b| b.to()),
                    extra_data: case.genesis_block_header.extra_data.clone(),
                    // EIP-4844 related fields
                    // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
                    blob_gas_used: case.genesis_block_header.blob_gas_used.map(|b| b.to()),
                    excess_blob_gas: case.genesis_block_header.excess_blob_gas.map(|b| b.to()),
                    // EIP-4788 related field
                    // unrelated for rollups
                    parent_beacon_block_root: None,
                    requests_root: None,
                };

                let block = Block {
                    header,
                    l1_fee_rate: 0,
                    l1_hash: B256::default(),
                    transactions: 0u64..0u64,
                };

                for (&address, account) in case.pre.0.iter() {
                    evm_config.data.push(AccountData::new(
                        address,
                        account.balance,
                        account.code.clone(),
                        account.nonce.saturating_to::<u64>(),
                        HashMap::new(),
                    ));
                }

                let (mut evm, _, mut storage) = get_evm_with_storage(&evm_config);
                let mut l2_height = 2;

                let mut working_set = WorkingSet::new(storage.clone());
                evm.cfg.set(
                    &EvmChainConfig {
                        chain_id: evm_config.chain_id,
                        limit_contract_code_size: evm_config.limit_contract_code_size,
                        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
                        coinbase: case.genesis_block_header.coinbase,
                        block_gas_limit: case.genesis_block_header.gas_limit.to(),
                        base_fee_params: evm_config.base_fee_params,
                    },
                    &mut working_set,
                );
                evm.latest_block_hashes.set(
                    &U256::from(0),
                    &case.genesis_block_header.hash,
                    &mut working_set,
                );
                evm.head.set(&block, &mut working_set);
                evm.pending_head
                    .set(&block, &mut working_set.accessory_state());
                evm.finalize_hook(
                    &case.genesis_block_header.state_root.0.into(),
                    &mut working_set.accessory_state(),
                );

                let root = case.genesis_block_header.state_root;

                // Decode and insert blocks, creating a chain of blocks for the test case.
                for block in case.blocks.iter() {
                    let decoded = SealedBlock::decode(&mut block.rlp.as_ref())?;
                    let txs: Vec<RlpEvmTransaction> = decoded
                        .body
                        .iter()
                        .map(|t| {
                            let mut buffer = Vec::<u8>::new();
                            t.encode(&mut buffer);
                            RlpEvmTransaction { rlp: buffer }
                        })
                        .collect();

                    (working_set, storage) = self.execute_transactions(
                        &mut evm,
                        txs,
                        working_set,
                        storage,
                        &root,
                        l2_height,
                    );

                    l2_height += 1;
                }

                // Validate the post-state for the test case.
                match (&case.post_state, &case.post_state_hash) {
                    (Some(state), None) => {
                        // Validate accounts in the state against the provider's database.
                        for (&address, account) in state.iter() {
                            if let Some(account_state) =
                                evm.accounts.get(&address, &mut working_set)
                            {
                                assert_eq!(U256::from(account_state.nonce), account.nonce);
                                assert_eq!(account_state.balance, account.balance);
                                assert_eq!(*account_state.code_hash.unwrap(), **account.code);
                                let db_account = DbAccount::new(address);
                                for (key, value) in account.storage.iter() {
                                    assert_eq!(
                                        db_account.storage.get(key, &mut working_set),
                                        Some(value).copied()
                                    );
                                }
                            }
                        }
                    }
                    (None, Some(expected_state_root)) => {
                        // Insert state hashes into the provider based on the expected state root.
                        assert_eq!(
                            *evm.head.get(&mut working_set).unwrap().header.state_root,
                            **expected_state_root
                        );
                    }
                    _ => return Err(Error::MissingPostState),
                }

                Ok(())
            })?;

        Ok(())
    }
}

/// Returns whether the test at the given path should be skipped.
///
/// Some tests are edge cases that cannot happen on mainnet, while others are skipped for
/// convenience (e.g. they take a long time to run) or are temporarily disabled.
///
/// The reason should be documented in a comment above the file name(s).
pub fn should_skip(path: &Path) -> bool {
    let path_str = path.to_str().expect("Path is not valid UTF-8");
    let name = path.file_name().unwrap().to_str().unwrap();
    matches!(
        name,
        // funky test with `bigint 0x00` value in json :) not possible to happen on mainnet and require
        // custom json parser. https://github.com/ethereum/tests/issues/971
        | "ValueOverflow.json"
        | "ValueOverflowParis.json"

        // txbyte is of type 02 and we dont parse tx bytes for this test to fail.
        | "typeTwoBerlin.json"

        // Test checks if nonce overflows. We are handling this correctly but we are not parsing
        // exception in testsuite There are more nonce overflow tests that are in internal
        // call/create, and those tests are passing and are enabled.
        | "CreateTransactionHighNonce.json"

        // Test check if gas price overflows, we handle this correctly but does not match tests specific
        // exception.
        | "HighGasPrice.json"
        | "HighGasPriceParis.json"

        // Skip test where basefee/accesslist/difficulty is present but it shouldn't be supported in
        // London/Berlin/TheMerge. https://github.com/ethereum/tests/blob/5b7e1ab3ffaf026d99d20b17bb30f533a2c80c8b/GeneralStateTests/stExample/eip1559.json#L130
        // It is expected to not execute these tests.
        | "accessListExample.json"
        | "basefeeExample.json"
        | "eip1559.json"
        | "mergeTest.json"

        // These tests are passing, but they take a lot of time to execute so we are going to skip them.
        | "loopExp.json"
        | "Call50000_sha256.json"
        | "static_Call50000_sha256.json"
        | "loopMul.json"
        | "CALLBlake2f_MaxRounds.json"
        | "shiftCombinations.json"
    )
    // Ignore outdated EOF tests that haven't been updated for Cancun yet.
    || path_contains(path_str, &["EIPTests", "stEOF"])
}

/// `str::contains` but for a path. Takes into account the OS path separator (`/` or `\`).
fn path_contains(path_str: &str, rhs: &[&str]) -> bool {
    let rhs = rhs.join(std::path::MAIN_SEPARATOR_STR);
    path_str.contains(&rhs)
}
