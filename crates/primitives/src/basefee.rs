use alloy_eips::eip1559::BaseFeeParams;
use reth_primitives::basefee::calc_next_block_base_fee;

use crate::MIN_BASE_FEE_PER_GAS;

pub fn calculate_next_block_base_fee(
    gas_used: u128,
    gas_limit: u128,
    base_fee: Option<u64>,
    base_fee_params: BaseFeeParams,
) -> Option<u64> {
    Some(std::cmp::max(
        MIN_BASE_FEE_PER_GAS,
        calc_next_block_base_fee(gas_used, gas_limit, base_fee? as u128, base_fee_params),
    ) as u64)
}
