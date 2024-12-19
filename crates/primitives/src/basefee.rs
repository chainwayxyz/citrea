use alloy_eips::eip1559::{calc_next_block_base_fee, BaseFeeParams};

use crate::MIN_BASE_FEE_PER_GAS;

pub fn calculate_next_block_base_fee(
    gas_used: u64,
    gas_limit: u64,
    base_fee: u64,
    base_fee_params: BaseFeeParams,
) -> u128 {
    std::cmp::max(
        MIN_BASE_FEE_PER_GAS,
        calc_next_block_base_fee(gas_used, gas_limit, base_fee, base_fee_params) as u128,
    )
}
