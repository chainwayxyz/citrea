#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "native")]
pub mod genesis_config;
mod hooks_impl;
pub mod runtime;
/// Implements the `StateTransitionVerifier` type for checking the validity of a state transition
pub mod verifier;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::da::DaVerifier;
use verifier::StateTransitionVerifier;

/// Alias for StateTransitionVerifier.
pub type StfVerifier<DA, ZkContext, RT> =
    StateTransitionVerifier<StfBlueprint<ZkContext, <DA as DaVerifier>::Spec, RT>, DA>;
