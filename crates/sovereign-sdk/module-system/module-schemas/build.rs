use std::fs::File;
use std::io::{self, Write};

use sov_mock_da::verifier::MockDaSpec;
use sov_mock_da::MockValidityCond;
use sov_mock_zkvm::MockZkvm;
use sov_modules_api::default_context::DefaultContext as C;
use sov_modules_api::ModuleCallJsonSchema;

fn main() -> io::Result<()> {
    store_json_schema::<sov_bank::Bank<C>>("sov-bank.json")?;
    store_json_schema::<sov_accounts::Accounts<C>>("sov-accounts.json")?;
    store_json_schema::<sov_value_setter::ValueSetter<C>>("sov-value-setter.json")?;
    store_json_schema::<sov_prover_incentives::ProverIncentives<C, MockZkvm<MockValidityCond>>>(
        "sov-prover-incentives.json",
    )?;
    store_json_schema::<sov_sequencer_registry::SequencerRegistry<C, MockDaSpec>>(
        "sov-sequencer-registry.json",
    )?;
    Ok(())
}

fn store_json_schema<M: ModuleCallJsonSchema>(filename: &str) -> io::Result<()> {
    let mut file = File::create(format!("schemas/{}", filename))?;
    file.write_all(M::json_schema().as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}
