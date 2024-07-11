#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};

use anyhow::ensure;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::zk::{Matches, StateTransitionData, ValidityCondition};

/// A mock commitment to a particular zkVM program.
#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct MockCodeCommitment(pub [u8; 32]);

impl Matches<MockCodeCommitment> for MockCodeCommitment {
    fn matches(&self, other: &MockCodeCommitment) -> bool {
        self.0 == other.0
    }
}

/// A mock proof generated by a zkVM.
#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct MockProof {
    /// The ID of the program this proof might be valid for.
    pub program_id: MockCodeCommitment,
    /// Whether the proof is valid.
    pub is_valid: bool,
    /// The tamper-proof outputs of the proof.
    pub log: Vec<u8>,
}

impl MockProof {
    /// Serializes a proof into a writer.
    pub fn encode(&self, mut writer: impl Write) {
        writer.write_all(&self.program_id.0).unwrap();
        let is_valid_byte = if self.is_valid { 1 } else { 0 };
        writer.write_all(&[is_valid_byte]).unwrap();
        writer.write_all(&self.log).unwrap();
    }

    /// Serializes a proof into a vector.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        self.encode(&mut encoded);
        encoded
    }

    /// Tries to deserialize a proof from a byte slice.
    pub fn decode(input: &[u8]) -> Result<Self, anyhow::Error> {
        ensure!(input.len() >= 33, "Input is too short");
        let program_id = MockCodeCommitment(input[0..32].try_into().unwrap());
        let is_valid = input[32] == 1;
        let log = input[33..].to_vec();
        Ok(Self {
            program_id,
            is_valid,
            log,
        })
    }
}

#[derive(Clone)]
struct Notifier {
    notified: Arc<Mutex<bool>>,
    cond: Arc<Condvar>,
}

impl Default for Notifier {
    fn default() -> Self {
        Self {
            notified: Arc::new(Mutex::new(false)),
            cond: Default::default(),
        }
    }
}

impl Notifier {
    fn wait(&self) {
        let mut notified = self.notified.lock().unwrap();
        while !*notified {
            notified = self.cond.wait(notified).unwrap();
        }
    }

    fn notify(&self) {
        let mut notified = self.notified.lock().unwrap();
        *notified = true;
        self.cond.notify_all();
    }
}

/// A mock implementing the zkVM trait.
#[derive(Clone)]
pub struct MockZkvm<ValidityCond> {
    worker_thread_notifier: Notifier,
    committed_data: VecDeque<Vec<u8>>,
    validity_condition: ValidityCond,
}

impl<ValidityCond> MockZkvm<ValidityCond> {
    /// Creates a new MockZkvm
    pub fn new(validity_condition: ValidityCond) -> Self {
        Self {
            worker_thread_notifier: Default::default(),
            committed_data: Default::default(),
            validity_condition,
        }
    }

    /// Simulates zk proof generation.
    pub fn make_proof(&self) {
        // We notify the worket thread.
        self.worker_thread_notifier.notify();
    }
}

impl<ValidityCond: ValidityCondition> sov_rollup_interface::zk::Zkvm for MockZkvm<ValidityCond> {
    type CodeCommitment = MockCodeCommitment;

    type Error = anyhow::Error;

    fn verify<'a>(
        serialized_proof: &'a [u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        let proof = MockProof::decode(serialized_proof)?;
        anyhow::ensure!(
            proof.program_id.matches(code_commitment),
            "Proof failed to verify against requested code commitment"
        );
        anyhow::ensure!(proof.is_valid, "Proof is not valid");
        Ok(&serialized_proof[33..])
    }

    fn verify_and_extract_output<
        Da: sov_rollup_interface::da::DaSpec,
        Root: serde::Serialize + serde::de::DeserializeOwned,
    >(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let output = Self::verify(serialized_proof, code_commitment)?;
        Ok(bincode::deserialize(output)?)
    }
}

impl<ValidityCond: ValidityCondition> sov_rollup_interface::zk::ZkvmHost
    for MockZkvm<ValidityCond>
{
    type Guest = MockZkGuest;

    fn add_hint<T: BorshSerialize>(&mut self, item: T) {
        let hint = borsh::to_vec(&item).unwrap();
        let proof_info = ProofInfo {
            hint,
            validity_condition: self.validity_condition,
        };

        let data = borsh::to_vec(&proof_info).unwrap();
        self.committed_data.push_back(data)
    }

    fn simulate_with_hints(&mut self) -> Self::Guest {
        MockZkGuest {}
    }

    fn run(&mut self, _with_proof: bool) -> Result<sov_rollup_interface::zk::Proof, anyhow::Error> {
        self.worker_thread_notifier.wait();
        let data = self.committed_data.pop_front().unwrap_or_default();
        Ok(sov_rollup_interface::zk::Proof::PublicInput(data))
    }

    fn extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        proof: &sov_rollup_interface::zk::Proof,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        match proof {
            sov_rollup_interface::zk::Proof::PublicInput(pub_input) => {
                let data: ProofInfo<Da::ValidityCondition> = bincode::deserialize(pub_input)?;
                let st: StateTransitionData<Root, (), Da> =
                    BorshDeserialize::deserialize(&mut &*data.hint)?;

                Ok(sov_rollup_interface::zk::StateTransition {
                    initial_state_root: st.initial_state_root,
                    final_state_root: st.final_state_root,
                    initial_batch_hash: st.initial_batch_hash,
                    validity_condition: data.validity_condition,
                    state_diff: Default::default(),
                    da_slot_hash: st.da_block_header_of_commitments.hash(),
                    sequencer_public_key: vec![],
                    sequencer_da_public_key: vec![],
                })
            }
            sov_rollup_interface::zk::Proof::Full(_) => {
                panic!("Mock DA doesn't generate real proofs")
            }
        }
    }
}

/// A mock implementing the Guest.
pub struct MockZkGuest {}

impl sov_rollup_interface::zk::Zkvm for MockZkGuest {
    type CodeCommitment = MockCodeCommitment;

    type Error = anyhow::Error;

    fn verify<'a>(
        _serialized_proof: &'a [u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        unimplemented!()
    }

    fn verify_and_extract_output<
        Da: sov_rollup_interface::da::DaSpec,
        Root: Serialize + serde::de::DeserializeOwned,
    >(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        unimplemented!()
    }
}

impl sov_rollup_interface::zk::ZkvmGuest for MockZkGuest {
    fn read_from_host<T: BorshDeserialize>(&self) -> T {
        unimplemented!()
    }

    fn commit<T: BorshSerialize>(&self, _item: &T) {
        unimplemented!()
    }
}

#[derive(Debug, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
struct ProofInfo<ValidityCond> {
    hint: Vec<u8>,
    validity_condition: ValidityCond,
}

#[test]
fn test_mock_proof_round_trip() {
    let proof = MockProof {
        program_id: MockCodeCommitment([1; 32]),
        is_valid: true,
        log: vec![2; 50],
    };

    let mut encoded = Vec::new();
    proof.encode(&mut encoded);

    let decoded = MockProof::decode(&encoded).unwrap();
    assert_eq!(proof, decoded);
}
