//! Test runners for `BlockchainTests` in <https://github.com/ethereum/tests>

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use alloy_rlp::{Decodable, Encodable};
use rayon::iter::{ParallelBridge, ParallelIterator};
use reth_primitives::SealedBlock;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, StateMapAccessor, WorkingSet};
use sov_prover_storage_manager::SnapshotManager;
use sov_state::{DefaultStorageSpec, ProverStorage};

use crate::ef_tests::models::{BlockchainTest, ForkSpec};
use crate::ef_tests::{Case, Error, Suite};
use crate::test_utils::{commit, get_evm_with_storage, GENESIS_STATE_ROOT};
use crate::{AccountData, Evm, EvmConfig, RlpEvmTransaction, U256};

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
        storage: ProverStorage<DefaultStorageSpec, SnapshotManager>,
        root: &[u8; 32],
    ) -> (
        WorkingSet<DefaultContext>,
        ProverStorage<DefaultStorageSpec, SnapshotManager>,
    ) {
        // Call begin_soft_confirmation_hook
        evm.begin_soft_confirmation_hook([0u8; 32], 0, [0u8; 32], root, 0, 0, &mut working_set);

        let dummy_address = generate_address::<DefaultContext>("dummy");
        let sequencer_address = generate_address::<DefaultContext>("sequencer");
        let context = DefaultContext::new(dummy_address, sequencer_address, 1);
        let _ = evm.execute_call(txs, &context, &mut working_set);

        evm.end_soft_confirmation_hook(&mut working_set);
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
            .filter(|case| {
                !matches!(
                    case.network,
                    ForkSpec::ByzantiumToConstantinopleAt5
                        | ForkSpec::Constantinople
                        | ForkSpec::ConstantinopleFix
                        | ForkSpec::MergeEOF
                        | ForkSpec::MergeMeterInitCode
                        | ForkSpec::MergePush0
                        | ForkSpec::Unknown
                )
            })
            .par_bridge()
            .try_for_each(|case| {
                let mut evm_config = EvmConfig::default();
                // Set this base fee specifically for ef-tests
                evm_config.starting_base_fee = 10;
                for (&address, account) in case.pre.0.iter() {
                    evm_config.data.push(AccountData::new(
                        address,
                        account.balance,
                        account.code.clone(),
                        HashMap::new(),
                    ));
                }

                let (mut evm, mut working_set, mut storage) = get_evm_with_storage(&evm_config);
                let root = &GENESIS_STATE_ROOT;

                // Decode and insert blocks, creating a chain of blocks for the test case.
                let mut it = case.blocks.iter().peekable();
                let last_block = loop {
                    let Some(block) = it.next() else {
                        break Ok::<Option<SealedBlock>, Error>(None);
                    };
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

                    (working_set, storage) =
                        self.execute_transactions(&mut evm, txs, working_set, storage, &root);

                    if it.peek().is_none() {
                        break Ok::<Option<SealedBlock>, Error>(Some(decoded));
                    }
                }?;

                // Validate the post-state for the test case.
                match (&case.post_state, &case.post_state_hash) {
                    (Some(state), None) => {
                        // Validate accounts in the state against the provider's database.
                        for (&address, account) in state.iter() {
                            if let Some(account_state) =
                                evm.accounts.get(&address, &mut working_set)
                            {
                                assert_eq!(U256::from(account_state.info.nonce), account.nonce);
                                assert_eq!(account_state.info.balance, account.balance);
                                // account.assert_db(address, provider.tx_ref())?;
                            }
                        }
                    }
                    (None, Some(expected_state_root)) => {
                        // Insert state hashes into the provider based on the expected state root.
                        let last_block = last_block.unwrap_or_default();
                        // provider
                        //     .insert_hashes(
                        //         0..=last_block.number,
                        //         last_block.hash(),
                        //         *expected_state_root,
                        //     )
                        //     .map_err(|err| Error::RethError(err.into()))?;
                        // TODO(@rakanalh) Add code for comparing state roots
                        unimplemented!(
                            "Last block {}, expected state root {}",
                            last_block.number,
                            expected_state_root
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

        // | "addNonConst.json"
        | "addmodNonConst.json"
        | "andNonConst.json"
        | "balanceNonConst.json"
        | "byteNonConst.json"
        | "callNonConst.json"
        | "callcodeNonConst.json"
        | "calldatacopyNonConst.json"
        | "calldataloadNonConst.json"
        | "codecopyNonConst.json"
        | "createNonConst.json"
        | "delegatecallNonConst.json"
        | "divNonConst.json"
        | "eqNonConst.json"
        | "expNonConst.json"
        | "extcodecopyNonConst.json"
        | "extcodesizeNonConst.json"
        | "gtNonConst.json"
        | "iszeroNonConst.json"
        | "jumpNonConst.json"
        | "jumpiNonConst.json"
        | "log0NonConst.json"
        | "log1NonConst.json"
        | "log2NonConst.json"
        | "log3NonConst.json"
        | "ltNonConst.json"
        | "mloadNonConst.json"
        | "modNonConst.json"
        | "mstore8NonConst.json"
        | "mstoreNonConst.json"
        | "mulNonConst.json"
        | "mulmodNonConst.json"
        | "notNonConst.json"
        | "orNonConst.json"
        | "returnNonConst.json"
        | "sdivNonConst.json"
        | "sgtNonConst.json"
        | "sha3NonConst.json"
        | "signextNonConst.json"
        | "sloadNonConst.json"
        | "sltNonConst.json"
        | "smodNonConst.json"
        | "sstoreNonConst.json"
        | "subNonConst.json"
        | "suicideNonConst.json"
        | "xorNonConst.json"

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
