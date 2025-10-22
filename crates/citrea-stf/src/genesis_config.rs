//! While the `GenesisConfig` type for `Rollup` is generated from the underlying runtime through a macro,
//! specific module configurations are obtained from files. This code is responsible for the logic
//! that transforms module genesis data into Rollup genesis data.

use std::convert::AsRef;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use citrea_evm::EvmConfig;
use l2_block_rule_enforcer::L2BlockRuleEnforcerConfig;
use sov_accounts::AccountConfig;
pub use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::Context;
use sov_modules_stf_blueprint::Runtime as RuntimeTrait;
use sov_rollup_interface::da::DaSpec;
pub use sov_state::config::Config as StorageConfig;

use crate::runtime::CitreaRuntime;
/// Creates config for a rollup with some default settings, the config is used in demos and tests.
use crate::runtime::GenesisConfig;

/// Paths pointing to genesis files.
pub struct GenesisPaths {
    /// Accounts genesis path.
    pub accounts_genesis_path: PathBuf,
    /// EVM genesis path.
    pub evm_genesis_path: PathBuf,
    /// L2 Block Rule Enforcer genesis path.
    pub l2_block_rule_enforcer_genesis_path: PathBuf,
}

impl GenesisPaths {
    /// Creates a new [`GenesisPaths`] from the files contained in the given
    /// directory.
    ///
    /// Take a look at the contents of the `test_data` directory to see the
    /// expected files.
    pub fn from_dir(dir: impl AsRef<Path>) -> Self {
        Self {
            accounts_genesis_path: dir.as_ref().join("accounts.json"),
            evm_genesis_path: dir.as_ref().join("evm.json"),
            l2_block_rule_enforcer_genesis_path: dir.as_ref().join("l2_block_rule_enforcer.json"),
        }
    }
}

/// Creates genesis configuration.
pub fn get_genesis_config<C: Context, Da: DaSpec>(
    genesis_paths: &GenesisPaths,
) -> Result<<CitreaRuntime<C, Da> as RuntimeTrait<C, Da>>::GenesisConfig, anyhow::Error> {
    let genesis_config =
        create_genesis_config(genesis_paths).context("Unable to read genesis configuration")?;
    validate_config(genesis_config)
}

pub(crate) fn validate_config<C: Context, Da: DaSpec>(
    genesis_config: <CitreaRuntime<C, Da> as RuntimeTrait<C, Da>>::GenesisConfig,
) -> Result<<CitreaRuntime<C, Da> as RuntimeTrait<C, Da>>::GenesisConfig, anyhow::Error> {
    Ok(genesis_config)
}

fn create_genesis_config<C: Context, Da: DaSpec>(
    genesis_paths: &GenesisPaths,
) -> anyhow::Result<<CitreaRuntime<C, Da> as RuntimeTrait<C, Da>>::GenesisConfig> {
    let accounts_config: AccountConfig = read_json_file(&genesis_paths.accounts_genesis_path)?;

    let evm_config: EvmConfig = read_json_file(&genesis_paths.evm_genesis_path)?;

    let l2_block_rule_enforcer_config: L2BlockRuleEnforcerConfig =
        read_json_file(&genesis_paths.l2_block_rule_enforcer_genesis_path)?;

    Ok(GenesisConfig::new(
        accounts_config,
        evm_config,
        l2_block_rule_enforcer_config,
    ))
}

/// Read genesis file
pub fn read_json_file<T: serde::de::DeserializeOwned, P: AsRef<Path>>(
    path: P,
) -> anyhow::Result<T> {
    let path_str = path.as_ref().display();

    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read genesis from {path_str}"))?;
    let config: T = serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse genesis from {path_str}"))?;

    Ok(config)
}
