use sov_modules_api::DaSpec;
use sov_rollup_interface::da::DaVerifier;

use crate::input::LightClientCircuitInput;
use crate::output::LightClientCircuitOutput;

pub enum LightClientVerificationError {}

pub fn run_circuit<DaV: DaVerifier, DaS: DaSpec>(
    input: LightClientCircuitInput<DaS>,
    da_verifier: DaV,
) -> Result<LightClientCircuitOutput, LightClientVerificationError> {
    todo!()
}
