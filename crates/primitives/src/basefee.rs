use alloy_eips::eip1559::{calc_next_block_base_fee, BaseFeeParams};
use sov_rollup_interface::spec::SpecId;

use crate::min_base_fee_per_gas;

pub fn calculate_next_block_base_fee(
    gas_used: u64,
    gas_limit: u64,
    base_fee: u64,
    base_fee_params: BaseFeeParams,
    spec_id: SpecId,
) -> u64 {
    std::cmp::max(
        min_base_fee_per_gas(spec_id),
        calc_next_block_base_fee(gas_used, gas_limit, base_fee, base_fee_params),
    )
}
