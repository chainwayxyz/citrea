#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "native")]
pub mod genesis_config;
mod hooks_impl;
pub mod runtime;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::da::DaVerifier;
use sov_stf_runner::verifier::StateTransitionVerifier;

/// Alias for StateTransitionVerifier.
pub type StfVerifier<DA, Vm, ZkContext, RT> =
    StateTransitionVerifier<StfBlueprint<ZkContext, <DA as DaVerifier>::Spec, Vm, RT>, DA, Vm>;
