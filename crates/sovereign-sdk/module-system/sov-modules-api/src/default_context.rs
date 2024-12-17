use std::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sov_modules_core::{Address, Context, PublicKey, Spec};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::RollupAddress;
#[cfg(feature = "native")]
use sov_state::ProverStorage;
use sov_state::{ArrayWitness, DefaultHasher, DefaultWitness, ZkStorage};

#[cfg(feature = "native")]
use crate::default_signature::private_key::DefaultPrivateKey;
use crate::default_signature::{DefaultPublicKey, DefaultSignature};

#[cfg(feature = "native")]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct DefaultContext {
    pub sender: Address,
    pub l1_fee_rate: u128,
    pub active_spec: SpecId,
    /// The height to report. This is set by the kernel when the context is created
    visible_height: u64,
}

#[cfg(feature = "native")]
impl Spec for DefaultContext {
    type Address = Address;
    type Storage = ProverStorage<sov_prover_storage_manager::SnapshotManager>;
    type PrivateKey = DefaultPrivateKey;
    type PublicKey = DefaultPublicKey;
    type Hasher = sha2::Sha256;
    type Signature = DefaultSignature;
    type Witness = ArrayWitness;
}

#[cfg(feature = "native")]
impl Context for DefaultContext {
    fn sender(&self) -> &Self::Address {
        &self.sender
    }

    fn new(sender: Self::Address, height: u64, active_spec: SpecId, l1_fee_rate: u128) -> Self {
        Self {
            sender,
            l1_fee_rate,
            active_spec,
            visible_height: height,
        }
    }

    fn slot_height(&self) -> u64 {
        self.visible_height
    }

    fn active_spec(&self) -> SpecId {
        self.active_spec
    }

    fn l1_fee_rate(&self) -> u128 {
        self.l1_fee_rate
    }
}

#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ZkDefaultContext {
    pub sender: Address,
    pub l1_fee_rate: u128,
    pub active_spec: SpecId,
    /// The height to report. This is set by the kernel when the context is created
    visible_height: u64,
}

impl Spec for ZkDefaultContext {
    type Address = Address;
    type Storage = ZkStorage<DefaultWitness, DefaultHasher>;
    #[cfg(feature = "native")]
    type PrivateKey = DefaultPrivateKey;
    type PublicKey = DefaultPublicKey;
    type Hasher = sha2::Sha256;
    type Signature = DefaultSignature;
    type Witness = ArrayWitness;
}

impl Context for ZkDefaultContext {
    fn sender(&self) -> &Self::Address {
        &self.sender
    }
    fn new(sender: Self::Address, height: u64, active_spec: SpecId, l1_fee_rate: u128) -> Self {
        Self {
            sender,
            active_spec,
            l1_fee_rate,
            visible_height: height,
        }
    }

    fn slot_height(&self) -> u64 {
        self.visible_height
    }

    fn active_spec(&self) -> SpecId {
        self.active_spec
    }

    fn l1_fee_rate(&self) -> u128 {
        self.l1_fee_rate
    }
}

impl PublicKey for DefaultPublicKey {
    fn to_address<A: RollupAddress>(&self) -> A {
        let pub_key_hash = {
            let mut hasher = <ZkDefaultContext as Spec>::Hasher::new();
            hasher.update(self.pub_key);
            hasher.finalize().into()
        };
        A::from(pub_key_hash)
    }
}
