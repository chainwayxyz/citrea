use std::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "native")]
use sov_keys::default_signature::k256_private_key::K256PrivateKey;
use sov_keys::default_signature::{K256PublicKey, K256Signature};
use sov_modules_core::{Address, Context, Spec};
use sov_rollup_interface::spec::SpecId;
#[cfg(feature = "native")]
use sov_state::ProverStorage;
use sov_state::ZkStorage;

#[cfg(feature = "native")]
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
    type Storage = ProverStorage;
    type PrivateKey = K256PrivateKey;
    type PublicKey = K256PublicKey;
    type Signature = K256Signature;
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
    type Storage = ZkStorage;
    #[cfg(feature = "native")]
    type PrivateKey = K256PrivateKey;
    type PublicKey = K256PublicKey;
    type Signature = K256Signature;
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
