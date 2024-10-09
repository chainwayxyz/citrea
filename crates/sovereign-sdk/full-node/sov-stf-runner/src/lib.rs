#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

/// Testing utilities.
#[cfg(feature = "mock")]
pub mod mock;
#[cfg(feature = "native")]
mod prover_service;

#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use anyhow::Context;
#[cfg(feature = "native")]
pub use prover_service::*;
#[cfg(feature = "native")]
use sov_modules_api::{DaSpec, Zkvm};
#[cfg(feature = "native")]
use sov_rollup_interface::stf::StateTransitionFunction;

#[cfg(feature = "native")]
type GenesisParams<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::GenesisParams;
#[cfg(feature = "native")]
type SoftConfirmationHash = [u8; 32];

#[cfg(feature = "native")]
/// Reads json file.
pub fn read_json_file<T: serde::de::DeserializeOwned, P: AsRef<Path>>(
    path: P,
) -> anyhow::Result<T> {
    let path_str = path.as_ref().display();

    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read genesis from {}", path_str))?;
    let config: T = serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse genesis from {}", path_str))?;

    Ok(config)
}

#[cfg(feature = "native")]
/// How [`StateTransitionRunner`] is initialized
pub enum InitVariant<Stf: StateTransitionFunction<Vm, Da>, Vm: Zkvm, Da: DaSpec> {
    /// From given state root and soft confirmation hash
    Initialized((Stf::StateRoot, SoftConfirmationHash)),
    /// From empty state root
    /// Genesis params for Stf::init
    Genesis(GenesisParams<Stf, Vm, Da>),
}
