use std::array::TryFromSliceError;
use std::ops::RangeInclusive;

use ethereum_types::U64;
use jsonrpsee::core::RpcResult;
use reth_interfaces::provider::ProviderError;
use reth_primitives::contract::create_address;
use reth_primitives::TransactionKind::{Call, Create};
use reth_primitives::{
    BlockId, BlockNumberOrTag, SealedHeader, TransactionSignedEcRecovered, U128, U256,
};
use revm::primitives::{
    EVMError, ExecutionResult, Halt, InvalidTransaction, TransactTo, KECCAK_EMPTY,
};
use sov_modules_api::macros::rpc_gen;
use sov_modules_api::prelude::*;
use sov_modules_api::WorkingSet;
use tracing::info;

use crate::call::get_cfg_env;
use crate::error::rpc::{ensure_success, EthApiError, RevertError, RpcInvalidTransactionError};
use crate::evm::db::EvmDb;
use crate::evm::primitive_types::{BlockEnv, Receipt, SealedBlock, TransactionSignedAndRecovered};
use crate::evm::{executor, prepare_call_env};
use crate::experimental::{MIN_CREATE_GAS, MIN_TRANSACTION_GAS};
use crate::rpc_helpers::*;
use crate::{BloomFilter, Evm, EvmChainConfig, FilterBlockOption, FilterError};

#[rpc_gen(client, server)]
impl<C: sov_modules_api::Context> Evm<C> {
    /// Handler for `net_version`
    #[rpc_method(name = "net_version")]
    pub fn net_version(&self, _working_set: &mut WorkingSet<C>) -> RpcResult<String> {
        info!("evm module: net_version");

        // Network ID is the same as chain ID for most networks
        let chain_id = self
            .cfg
            .get(_working_set)
            .expect("Evm config must be set")
            .chain_id;

        Ok(chain_id.to_string())
    }

    /// Handler for: `eth_chainId`
    #[rpc_method(name = "eth_chainId")]
    pub fn chain_id(
        &self,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<Option<reth_primitives::U64>> {
        info!("evm module: eth_chainId");

        let chain_id = reth_primitives::U64::from(
            self.cfg
                .get(working_set)
                .expect("Evm config must be set")
                .chain_id,
        );

        Ok(Some(chain_id))
    }

    /// Handler for `eth_getBlockByHash`
    #[rpc_method(name = "eth_getBlockByHash")]
    pub fn get_block_by_hash(
        &self,
        block_hash: reth_primitives::H256,
        details: Option<bool>,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<Option<reth_rpc_types::RichBlock>> {
        info!("evm module: eth_getBlockByHash");

        let block_number = self
            .block_hashes
            .get(&block_hash, &mut working_set.accessory_state())
            .expect("Block number for known block hash must be set");

        self.get_block_by_number(
            Some(BlockNumberOrTag::Number(block_number)),
            details,
            working_set,
        )
    }

    /// Handler for: `eth_getBlockByNumber`
    #[rpc_method(name = "eth_getBlockByNumber")]
    pub fn get_block_by_number(
        &self,
        block_number: Option<BlockNumberOrTag>,
        details: Option<bool>,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<Option<reth_rpc_types::RichBlock>> {
        info!("evm module: eth_getBlockByNumber");

        let block = self.get_sealed_block_by_number(block_number, working_set);

        // Build rpc header response
        let header = reth_rpc_types::Header::from_primitive_with_hash(block.header.clone());

        // Collect transactions with ids from db
        let transactions_with_ids = block.transactions.clone().map(|id| {
            let tx = self
                .transactions
                .get(id as usize, &mut working_set.accessory_state())
                .expect("Transaction must be set");
            (id, tx)
        });

        // Build rpc transactions response
        let transactions = match details {
            Some(true) => reth_rpc_types::BlockTransactions::Full(
                transactions_with_ids
                    .map(|(id, tx)| {
                        reth_rpc_types_compat::from_recovered_with_block_context(
                            tx.clone().into(),
                            block.header.hash,
                            block.header.number,
                            block.header.base_fee_per_gas,
                            U256::from(id - block.transactions.start),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => reth_rpc_types::BlockTransactions::Hashes({
                transactions_with_ids
                    .map(|(_, tx)| tx.signed_transaction.hash)
                    .collect::<Vec<_>>()
            }),
        };

        // Build rpc block response
        let total_difficulty = Some(block.header.difficulty);
        let block = reth_rpc_types::Block {
            header,
            total_difficulty,
            uncles: Default::default(),
            transactions,
            size: Default::default(),
            withdrawals: Default::default(),
        };

        Ok(Some(block.into()))
    }

    /// Handler for: `eth_getBlockReceipts`
    #[rpc_method(name = "eth_getBlockReceipts")]
    pub fn get_block_receipts(
        &self,
        block_number_or_hash: BlockId,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<Option<Vec<reth_rpc_types::TransactionReceipt>>> {
        info!("evm module: eth_getBlockReceipts");

        let block = match block_number_or_hash {
            BlockId::Hash(block_hash) => {
                let block_number = self
                    .block_hashes
                    .get(&block_hash.block_hash, &mut working_set.accessory_state())
                    .expect("Block number for known block hash must be set");

                self.blocks
                    .get(block_number as usize, &mut working_set.accessory_state())
                    .expect("Block must be set")
            }
            BlockId::Number(block_number) => {
                self.get_sealed_block_by_number(Some(block_number.into()), working_set)
            }
        };

        let receipts = &block
            .transactions
            .clone()
            .map(|id| {
                let tx = self
                    .transactions
                    .get(id as usize, &mut working_set.accessory_state())
                    .expect("Transaction must be set");

                let receipt = self
                    .receipts
                    .get(id as usize, &mut working_set.accessory_state())
                    .expect("Receipt for known transaction must be set");

                build_rpc_receipt(&block, tx, id, receipt)
            })
            .collect::<Vec<_>>();

        Ok(Some(receipts.clone()))
    }

    /// Handler for: `eth_getBalance`
    #[rpc_method(name = "eth_getBalance")]
    pub fn get_balance(
        &self,
        address: reth_primitives::Address,
        _block_number: Option<BlockNumberOrTag>,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<reth_primitives::U256> {
        info!("evm module: eth_getBalance");

        // TODO: Implement block_number once we have archival state #951
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/951

        let balance = self
            .accounts
            .get(&address, working_set)
            .map(|account| account.info.balance)
            .unwrap_or_default();

        Ok(balance)
    }

    /// Handler for: `eth_getStorageAt`
    #[rpc_method(name = "eth_getStorageAt")]
    pub fn get_storage_at(
        &self,
        address: reth_primitives::Address,
        index: reth_primitives::U256,
        _block_number: Option<BlockNumberOrTag>,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<reth_primitives::U256> {
        info!("evm module: eth_getStorageAt");

        // TODO: Implement block_number once we have archival state #951
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/951

        let storage_slot = self
            .accounts
            .get(&address, working_set)
            .and_then(|account| account.storage.get(&index, working_set))
            .unwrap_or_default();

        Ok(storage_slot)
    }

    /// Handler for: `eth_getTransactionCount`
    #[rpc_method(name = "eth_getTransactionCount")]
    pub fn get_transaction_count(
        &self,
        address: reth_primitives::Address,
        _block_number: Option<BlockNumberOrTag>,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<reth_primitives::U64> {
        info!("evm module: eth_getTransactionCount");

        // TODO: Implement block_number once we have archival state #882
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/882

        let nonce = self
            .accounts
            .get(&address, working_set)
            .map(|account| account.info.nonce)
            .unwrap_or_default();

        Ok(nonce.into())
    }

    /// Handler for: `eth_getCode`
    #[rpc_method(name = "eth_getCode")]
    pub fn get_code(
        &self,
        address: reth_primitives::Address,
        _block_number: Option<BlockNumberOrTag>,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<reth_primitives::Bytes> {
        info!("evm module: eth_getCode");

        // TODO: Implement block_number once we have archival state #951
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/951

        let code = self
            .accounts
            .get(&address, working_set)
            .and_then(|account| self.code.get(&account.info.code_hash, working_set))
            .unwrap_or_default();

        Ok(code)
    }

    /// Handler for: `eth_getTransactionByHash`
    // TODO https://github.com/Sovereign-Labs/sovereign-sdk/issues/502
    #[rpc_method(name = "eth_getTransactionByHash")]
    pub fn get_transaction_by_hash(
        &self,
        hash: reth_primitives::H256,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<Option<reth_rpc_types::Transaction>> {
        info!("evm module: eth_getTransactionByHash");
        let mut accessory_state = working_set.accessory_state();

        let tx_number = self.transaction_hashes.get(&hash, &mut accessory_state);

        let transaction = tx_number.map(|number| {
            let tx = self
                .transactions
                .get(number as usize, &mut accessory_state)
                .unwrap_or_else(|| panic!("Transaction with known hash {} and number {} must be set in all {} transaction",                
                hash,
                number,
                self.transactions.len(&mut accessory_state)));

            let block = self
                .blocks
                .get(tx.block_number as usize, &mut accessory_state)
                .unwrap_or_else(|| panic!("Block with number {} for known transaction {} must be set",
                    tx.block_number,
                    tx.signed_transaction.hash));

            reth_rpc_types_compat::from_recovered_with_block_context(
                tx.into(),
                block.header.hash,
                block.header.number,
                block.header.base_fee_per_gas,
                U256::from(tx_number.unwrap() - block.transactions.start),
            )
        });

        Ok(transaction)
    }

    /// Handler for: `eth_getTransactionByBlockHashAndIndex`
    #[rpc_method(name = "eth_getTransactionByBlockHashAndIndex")]
    pub fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: reth_primitives::H256,
        index: reth_primitives::U64,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<Option<reth_rpc_types::Transaction>> {
        info!("evm module: eth_getTransactionByBlockHashAndIndex");

        let mut accessory_state = working_set.accessory_state();

        let block_number = self
            .block_hashes
            .get(&block_hash, &mut accessory_state)
            .expect("Block number for known block hash must be set");

        let block = self
            .blocks
            .get(block_number as usize, &mut accessory_state)
            .expect("Block must be set");

        let tx_number = block.transactions.start + index.as_u64();

        let tx = self
            .transactions
            .get(tx_number as usize, &mut accessory_state)
            .expect("Transaction must be set");

        let block = self
            .blocks
            .get(tx.block_number as usize, &mut accessory_state)
            .expect("Block number for known transaction must be set");

        let transaction = reth_rpc_types_compat::from_recovered_with_block_context(
            tx.into(),
            block.header.hash,
            block.header.number,
            block.header.base_fee_per_gas,
            U256::from(tx_number - block.transactions.start),
        );

        Ok(Some(transaction))
    }

    /// Handler for: `eth_getTransactionByBlockNumberAndIndex`
    #[rpc_method(name = "eth_getTransactionByBlockNumberAndIndex")]
    pub fn get_transaction_by_block_number_and_index(
        &self,
        block_number: BlockNumberOrTag,
        index: reth_primitives::U64,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<Option<reth_rpc_types::Transaction>> {
        info!("evm module: eth_getTransactionByBlockNumberAndIndex");

        let block_number = self.block_number_for_id(&block_number, working_set);

        let block = self
            .blocks
            .get(
                block_number.unwrap() as usize,
                &mut working_set.accessory_state(),
            )
            .expect("Block must be set");

        let tx_number = block.transactions.start + index.as_u64();

        let tx = self
            .transactions
            .get(tx_number as usize, &mut working_set.accessory_state())
            .expect("Transaction must be set");

        let block = self
            .blocks
            .get(tx.block_number as usize, &mut working_set.accessory_state())
            .expect("Block number for known transaction must be set");

        let transaction = reth_rpc_types_compat::from_recovered_with_block_context(
            tx.into(),
            block.header.hash,
            block.header.number,
            block.header.base_fee_per_gas,
            U256::from(tx_number - block.transactions.start),
        );

        Ok(Some(transaction))
    }

    /// Handler for: `eth_getTransactionReceipt`
    // TODO https://github.com/Sovereign-Labs/sovereign-sdk/issues/502
    #[rpc_method(name = "eth_getTransactionReceipt")]
    pub fn get_transaction_receipt(
        &self,
        hash: reth_primitives::H256,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<Option<reth_rpc_types::TransactionReceipt>> {
        info!("evm module: eth_getTransactionReceipt");
        let mut accessory_state = working_set.accessory_state();

        let tx_number = self.transaction_hashes.get(&hash, &mut accessory_state);

        let receipt = tx_number.map(|number| {
            let tx = self
                .transactions
                .get(number as usize, &mut accessory_state)
                .expect("Transaction with known hash must be set");
            let block = self
                .blocks
                .get(tx.block_number as usize, &mut accessory_state)
                .expect("Block number for known transaction must be set");

            let receipt = self
                .receipts
                .get(tx_number.unwrap() as usize, &mut accessory_state)
                .expect("Receipt for known transaction must be set");

            build_rpc_receipt(&block, tx, tx_number.unwrap(), receipt)
        });

        Ok(receipt)
    }

    /// Handler for: `eth_call`
    //https://github.com/paradigmxyz/reth/blob/f577e147807a783438a3f16aad968b4396274483/crates/rpc/rpc/src/eth/api/transactions.rs#L502
    //https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc-types/src/eth/call.rs#L7
    #[rpc_method(name = "eth_call")]
    pub fn get_call(
        &self,
        request: reth_rpc_types::CallRequest,
        block_number: Option<BlockNumberOrTag>,
        _state_overrides: Option<reth_rpc_types::state::StateOverride>,
        _block_overrides: Option<Box<reth_rpc_types::BlockOverrides>>,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<reth_primitives::Bytes> {
        info!("evm module: eth_call");
        let block_env = match block_number {
            Some(BlockNumberOrTag::Pending) => {
                self.block_env.get(working_set).unwrap_or_default().clone()
            }
            _ => {
                let block = self.get_sealed_block_by_number(block_number, working_set);
                BlockEnv::from(&block)
            }
        };

        let tx_env = prepare_call_env(&block_env, request.clone()).unwrap();

        let cfg = self.cfg.get(working_set).unwrap_or_default();
        let cfg_env = get_cfg_env(&block_env, cfg, Some(get_cfg_env_template()));

        let evm_db: EvmDb<'_, C> = self.get_db(working_set);

        let result = match executor::inspect(evm_db, &block_env, tx_env, cfg_env) {
            Ok(result) => result.result,
            Err(err) => return Err(EthApiError::from(err).into()),
        };

        Ok(ensure_success(result)?)
    }

    /// Handler for: `eth_blockNumber`
    #[rpc_method(name = "eth_blockNumber")]
    pub fn block_number(
        &self,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<reth_primitives::U256> {
        info!("evm module: eth_blockNumber");

        let block_number = U256::from(
            self.blocks
                .len(&mut working_set.accessory_state())
                .saturating_sub(1),
        );
        Ok(block_number)
    }

    /// Handler for: `eth_estimateGas`
    // https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc/src/eth/api/call.rs#L172
    #[rpc_method(name = "eth_estimateGas")]
    pub fn eth_estimate_gas(
        &self,
        request: reth_rpc_types::CallRequest,
        block_number: Option<BlockNumberOrTag>,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<reth_primitives::U64> {
        info!("evm module: eth_estimateGas");
        let mut block_env = match block_number {
            Some(BlockNumberOrTag::Pending) => {
                self.block_env.get(working_set).unwrap_or_default().clone()
            }
            _ => {
                let block = self.get_sealed_block_by_number(block_number, working_set);
                BlockEnv::from(&block)
            }
        };

        let tx_env = prepare_call_env(&block_env, request.clone()).unwrap();

        let cfg = self.cfg.get(working_set).unwrap_or_default();
        let cfg_env = get_cfg_env(&block_env, cfg, Some(get_cfg_env_template()));

        let request_gas = request.gas;
        let request_gas_price = request.gas_price;
        let env_gas_limit = block_env.gas_limit;

        // get the highest possible gas limit, either the request's set value or the currently
        // configured gas limit
        let mut highest_gas_limit = request.gas.unwrap_or(U256::from(env_gas_limit));

        let account = self
            .accounts
            .get(&tx_env.caller, working_set)
            .map(|account| account.info)
            .unwrap_or_default();

        // if the request is a simple transfer we can optimize
        if tx_env.data.is_empty() {
            if let TransactTo::Call(to) = tx_env.transact_to {
                let to_account = self
                    .accounts
                    .get(&to, working_set)
                    .map(|account| account.info)
                    .unwrap_or_default();
                if KECCAK_EMPTY == to_account.code_hash {
                    // simple transfer, check if caller has sufficient funds
                    let available_funds = account.balance;

                    if tx_env.value > available_funds {
                        return Err(RpcInvalidTransactionError::InsufficientFundsForTransfer.into());
                    }
                    return Ok(U64::from(MIN_TRANSACTION_GAS));
                }
            }
        }

        // check funds of the sender
        if tx_env.gas_price > U256::ZERO {
            // allowance is (balance - tx.value) / tx.gas_price
            let allowance = (account.balance - tx_env.value) / tx_env.gas_price;

            if highest_gas_limit > allowance {
                // cap the highest gas limit by max gas caller can afford with given gas price
                highest_gas_limit = allowance;
            }
        }

        // if the provided gas limit is less than computed cap, use that
        let gas_limit = std::cmp::min(U256::from(tx_env.gas_limit), highest_gas_limit);
        block_env.gas_limit = convert_u256_to_u64(gas_limit).unwrap();

        let evm_db = self.get_db(working_set);

        // execute the call without writing to db
        let result = executor::inspect(evm_db, &block_env, tx_env.clone(), cfg_env.clone());

        // Exceptional case: init used too much gas, we need to increase the gas limit and try
        // again
        if let Err(EVMError::Transaction(InvalidTransaction::CallerGasLimitMoreThanBlock)) = result
        {
            // if price or limit was included in the request then we can execute the request
            // again with the block's gas limit to check if revert is gas related or not
            if request_gas.is_some() || request_gas_price.is_some() {
                let evm_db = self.get_db(working_set);
                return Err(map_out_of_gas_err(block_env, tx_env, cfg_env, evm_db).into());
            }
        }

        let result = match result {
            Ok(result) => match result.result {
                ExecutionResult::Success { .. } => result.result,
                ExecutionResult::Halt { reason, gas_used } => {
                    return Err(RpcInvalidTransactionError::halt(reason, gas_used).into())
                }
                ExecutionResult::Revert { output, .. } => {
                    // if price or limit was included in the request then we can execute the request
                    // again with the block's gas limit to check if revert is gas related or not
                    return if request_gas.is_some() || request_gas_price.is_some() {
                        let evm_db = self.get_db(working_set);
                        Err(map_out_of_gas_err(block_env, tx_env, cfg_env, evm_db).into())
                    } else {
                        // the transaction did revert
                        Err(RpcInvalidTransactionError::Revert(RevertError::new(output)).into())
                    };
                }
            },
            Err(err) => return Err(EthApiError::from(err).into()),
        };

        // at this point we know the call succeeded but want to find the _best_ (lowest) gas the
        // transaction succeeds with. we  find this by doing a binary search over the
        // possible range NOTE: this is the gas the transaction used, which is less than the
        // transaction requires to succeed
        let gas_used = result.gas_used();
        // the lowest value is capped by the gas it takes for a transfer
        let mut lowest_gas_limit = if tx_env.transact_to.is_create() {
            MIN_CREATE_GAS
        } else {
            MIN_TRANSACTION_GAS
        };
        let mut highest_gas_limit: u64 = highest_gas_limit.try_into().unwrap_or(u64::MAX);
        // pick a point that's close to the estimated gas
        let mut mid_gas_limit = std::cmp::min(
            gas_used * 3,
            ((highest_gas_limit as u128 + lowest_gas_limit as u128) / 2) as u64,
        );
        // binary search
        while (highest_gas_limit - lowest_gas_limit) > 1 {
            let mut tx_env = tx_env.clone();
            tx_env.gas_limit = mid_gas_limit;

            let evm_db = self.get_db(working_set);
            let result = executor::inspect(evm_db, &block_env, tx_env.clone(), cfg_env.clone());

            // Exceptional case: init used too much gas, we need to increase the gas limit and try
            // again
            if let Err(EVMError::Transaction(InvalidTransaction::CallerGasLimitMoreThanBlock)) =
                result
            {
                // increase the lowest gas limit
                lowest_gas_limit = mid_gas_limit;

                // new midpoint
                mid_gas_limit = ((highest_gas_limit as u128 + lowest_gas_limit as u128) / 2) as u64;
                continue;
            }

            match result {
                Ok(result) => match result.result {
                    ExecutionResult::Success { .. } => {
                        // cap the highest gas limit with succeeding gas limit
                        highest_gas_limit = mid_gas_limit;
                    }
                    ExecutionResult::Revert { .. } => {
                        // increase the lowest gas limit
                        lowest_gas_limit = mid_gas_limit;
                    }
                    ExecutionResult::Halt { reason, .. } => {
                        match reason {
                            Halt::OutOfGas(_) => {
                                // increase the lowest gas limit
                                lowest_gas_limit = mid_gas_limit;
                            }
                            err => {
                                // these should be unreachable because we know the transaction succeeds,
                                // but we consider these cases an error
                                return Err(RpcInvalidTransactionError::EvmHalt(err).into());
                            }
                        }
                    }
                },
                Err(err) => return Err(EthApiError::from(err).into()),
            };

            // new midpoint
            mid_gas_limit = ((highest_gas_limit as u128 + lowest_gas_limit as u128) / 2) as u64;
        }

        Ok(U64::from(highest_gas_limit))
    }

    /// Returns logs matching given filter object.
    ///
    /// Handler for `eth_getLogs`
    #[rpc_method(name = "eth_getLogs")]
    pub fn eth_get_logs(
        &self,
        filter: Filter,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<Vec<LogResponse>> {
        // https://github.com/paradigmxyz/reth/blob/8892d04a88365ba507f28c3314d99a6b54735d3f/crates/rpc/rpc/src/eth/filter.rs#L302
        Ok(self.logs_for_filter(filter, working_set)?)
    }

    // https://github.com/paradigmxyz/reth/blob/8892d04a88365ba507f28c3314d99a6b54735d3f/crates/rpc/rpc/src/eth/filter.rs#L349
    fn logs_for_filter(
        &self,
        filter: Filter,
        working_set: &mut WorkingSet<C>,
    ) -> Result<Vec<LogResponse>, FilterError> {
        match filter.block_option {
            FilterBlockOption::AtBlockHash(block_hash) => {
                let block_number = self
                    .block_hashes
                    .get(&block_hash, &mut working_set.accessory_state());
                if block_number.is_none() {
                    return Err(FilterError::EthAPIError(
                        ProviderError::BlockHashNotFound(block_hash).into(),
                    ));
                }

                let block = self.blocks.get(
                    block_number.unwrap() as usize,
                    &mut working_set.accessory_state(),
                );
                if block.is_none() {
                    return Err(FilterError::EthAPIError(
                        ProviderError::BlockBodyIndicesNotFound(block_number.unwrap()).into(),
                    ));
                }

                // all of the logs we have in the block
                let mut all_logs: Vec<LogResponse> = Vec::new();

                self.append_matching_block_logs(
                    working_set,
                    &mut all_logs,
                    &filter,
                    block.unwrap(),
                );

                Ok(all_logs)
            }
            FilterBlockOption::Range {
                from_block,
                to_block,
            } => {
                // we start at the most recent block if unset in filter
                let start_block = self
                    .blocks
                    .last(&mut working_set.accessory_state())
                    .expect("Head block must be set")
                    .header
                    .number;
                let from = from_block
                    .map(|num| convert_block_number(num, start_block))
                    .transpose()?
                    .flatten();
                let to = to_block
                    .map(|num| convert_block_number(num, start_block))
                    .transpose()?
                    .flatten();
                let (from_block_number, to_block_number) =
                    get_filter_block_range(from, to, start_block);
                self.get_logs_in_block_range(
                    working_set,
                    &filter,
                    from_block_number,
                    to_block_number,
                )
            }
        }
    }

    // https://github.com/paradigmxyz/reth/blob/8892d04a88365ba507f28c3314d99a6b54735d3f/crates/rpc/rpc/src/eth/filter.rs#L423
    /// Returns all logs in the given _inclusive_ range that match the filter
    ///
    /// Returns an error if:
    ///  - underlying database error
    ///  - amount of matches exceeds configured limit
    fn get_logs_in_block_range(
        &self,
        working_set: &mut WorkingSet<C>,
        filter: &Filter,
        from_block_number: u64,
        to_block_number: u64,
    ) -> Result<Vec<LogResponse>, FilterError> {
        let max_blocks_per_filter: u64 = DEFAULT_MAX_BLOCKS_PER_FILTER;
        if to_block_number - from_block_number >= max_blocks_per_filter {
            return Err(FilterError::QueryExceedsMaxBlocks(max_blocks_per_filter));
        }
        // all of the logs we have in the block
        let mut all_logs: Vec<LogResponse> = Vec::new();

        let address_filter: BloomFilter = filter.address.to_bloom_filter();
        let topics_filter: Vec<BloomFilter> =
            filter.topics.iter().map(|t| t.to_bloom_filter()).collect();

        let max_headers_range = MAX_HEADERS_RANGE;

        // loop over the range of new blocks and check logs if the filter matches the log's bloom
        // filter
        for (from, to) in
            BlockRangeInclusiveIter::new(from_block_number..=to_block_number, max_headers_range)
        {
            for idx in from..=to {
                let block = self.blocks.get(
                    // Index from +1 or just from?
                    (idx) as usize,
                    &mut working_set.accessory_state(),
                );
                if block.is_none() {
                    return Err(FilterError::EthAPIError(
                        ProviderError::BlockBodyIndicesNotFound(idx).into(),
                    ));
                }
                let block = block.unwrap();
                let logs_bloom = block.header.logs_bloom;

                let alloy_logs_bloom = alloy_primitives::Bloom::from(logs_bloom.data());
                if matches_address(alloy_logs_bloom, &address_filter)
                    && matches_topics(alloy_logs_bloom, &topics_filter)
                {
                    self.append_matching_block_logs(working_set, &mut all_logs, &filter, block);
                    let max_logs_per_response = DEFAULT_MAX_LOGS_PER_RESPONSE;
                    // size check but only if range is multiple blocks, so we always return all
                    // logs of a single block
                    let is_multi_block_range = from_block_number != to_block_number;
                    if is_multi_block_range && all_logs.len() > max_logs_per_response {
                        return Err(FilterError::QueryExceedsMaxResults(max_logs_per_response));
                    }
                }
            }
        }
        Ok(all_logs)
    }

    // https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc/src/eth/logs_utils.rs#L21
    fn append_matching_block_logs(
        &self,
        working_set: &mut WorkingSet<C>,
        all_logs: &mut Vec<LogResponse>,
        filter: &Filter,
        block: SealedBlock,
    ) {
        // tracks the index of a log in the entire block
        let mut log_index: u32 = 0;

        // TODO: Understand how to handle this
        // TAG - true when the log was removed, due to a chain reorganization. false if its a valid log.
        let removed = false;

        let topics = filter.topics.clone();
        let tx_range = block.transactions;

        for i in tx_range {
            let receipt = self
                .receipts
                .get(i as usize, &mut working_set.accessory_state())
                .expect("Transaction must be set");
            let tx = self
                .transactions
                .get(i as usize, &mut working_set.accessory_state())
                .unwrap();
            let logs = receipt.receipt.logs;

            for log in logs.into_iter() {
                if log_matches_filter(
                    &log,
                    &filter,
                    &topics,
                    &block.header.hash,
                    &block.header.number,
                ) {
                    let log = LogResponse {
                        address: log.address,
                        topics: log.topics,
                        data: log.data.to_vec().into(),
                        block_hash: Some(block.header.hash),
                        block_number: Some(U256::from(block.header.number)),
                        transaction_hash: Some(tx.signed_transaction.hash),
                        transaction_index: Some(U256::from(i)),
                        log_index: Some(U256::from(log_index)),
                        removed,
                    };
                    all_logs.push(log);
                }
                log_index += 1;
            }
        }
    }

    /// Helper function to get chain config
    pub fn get_chain_config(&self, working_set: &mut WorkingSet<C>) -> EvmChainConfig {
        self.cfg.get(working_set).unwrap_or_default()
    }

    /// Helper function to get block hash from block number
    pub fn block_hash_from_number(
        &self,
        block_number: u64,
        working_set: &mut WorkingSet<C>,
    ) -> Option<reth_primitives::H256> {
        let block = self
            .blocks
            .get(block_number as usize, &mut working_set.accessory_state())?;
        Some(block.header.hash)
    }

    /// Helper function to get headers in range
    pub fn sealed_headers_range(
        &self,
        range: RangeInclusive<u64>,
        working_set: &mut WorkingSet<C>,
    ) -> Result<Vec<SealedHeader>, EthApiError> {
        let mut headers = Vec::new();
        for i in range {
            let block = self
                .blocks
                .get(i as usize, &mut working_set.accessory_state())
                .ok_or_else(|| EthApiError::InvalidBlockRange)?;
            headers.push(block.header);
        }
        Ok(headers)
    }

    /// Helper function to get transactions and receipts for a given block hash
    pub fn get_transactions_and_receipts(
        &self,
        block_hash: reth_primitives::H256,
        working_set: &mut WorkingSet<C>,
    ) -> Result<
        (
            Vec<reth_rpc_types::Transaction>,
            Vec<reth_rpc_types::TransactionReceipt>,
        ),
        EthApiError,
    > {
        let mut accessory_state = working_set.accessory_state();

        let block_number = self
            .block_hashes
            .get(&block_hash, &mut accessory_state)
            .ok_or_else(|| EthApiError::InvalidBlockRange)?;

        let block = self
            .blocks
            .get(block_number as usize, &mut accessory_state)
            .ok_or_else(|| EthApiError::InvalidBlockRange)?;

        let transactions = block
            .transactions
            .clone()
            .map(|id| {
                let tx = self
                    .transactions
                    .get(id as usize, &mut accessory_state)
                    .expect("Transaction must be set");
                let block = self
                    .blocks
                    .get(tx.block_number as usize, &mut accessory_state)
                    .expect("Block number for known transaction must be set");

                reth_rpc_types_compat::from_recovered_with_block_context(
                    tx.into(),
                    block.header.hash,
                    block.header.number,
                    block.header.base_fee_per_gas,
                    U256::from(id - block.transactions.start),
                )
            })
            .collect::<Vec<_>>();

        let receipts = block
            .transactions
            .clone()
            .map(|id| {
                let tx = self
                    .transactions
                    .get(id as usize, &mut accessory_state)
                    .expect("Transaction must be set");
                let block = self
                    .blocks
                    .get(tx.block_number as usize, &mut accessory_state)
                    .expect("Block number for known transaction must be set");

                let receipt = self
                    .receipts
                    .get(id as usize, &mut accessory_state)
                    .expect("Receipt for known transaction must be set");

                build_rpc_receipt(&block, tx, id, receipt)
            })
            .collect::<Vec<_>>();

        Ok((transactions, receipts))
    }

    /// Helper function to check if the block number is valid
    pub fn block_number_for_id(
        &self,
        block_id: &BlockNumberOrTag,
        working_set: &mut WorkingSet<C>,
    ) -> Option<u64> {
        match block_id {
            BlockNumberOrTag::Earliest => Some(0),
            BlockNumberOrTag::Latest => self
                .blocks
                .last(&mut working_set.accessory_state())
                .map(|block| block.header.number),
            BlockNumberOrTag::Number(block_number) => {
                if *block_number < self.blocks.len(&mut working_set.accessory_state()) as u64 {
                    Some(*block_number)
                } else {
                    None
                }
            }
            _ => {
                todo!();
            }
        }
    }

    fn get_sealed_block_by_number(
        &self,
        block_number: Option<BlockNumberOrTag>,
        working_set: &mut WorkingSet<C>,
    ) -> SealedBlock {
        // safe, finalized, and pending are not supported
        match block_number {
            Some(BlockNumberOrTag::Number(block_number)) => self
                .blocks
                .get(block_number as usize, &mut working_set.accessory_state())
                .expect("Block must be set"),
            Some(BlockNumberOrTag::Earliest) => self
                .blocks
                .get(0, &mut working_set.accessory_state())
                .expect("Genesis block must be set"),
            Some(BlockNumberOrTag::Latest) => self
                .blocks
                .last(&mut working_set.accessory_state())
                .expect("Head block must be set"),
            None => self
                .blocks
                .last(&mut working_set.accessory_state())
                .expect("Head block must be set"),
            _ => panic!("Unsupported block number type"),
        }
    }
}

fn get_cfg_env_template() -> revm::primitives::CfgEnv {
    let mut cfg_env = revm::primitives::CfgEnv::default();
    // Reth sets this to true and uses only timeout, but other clients use this as a part of DOS attacks protection, with 100mln gas limit
    // https://github.com/paradigmxyz/reth/blob/62f39a5a151c5f4ddc9bf0851725923989df0412/crates/rpc/rpc/src/eth/revm_utils.rs#L215
    cfg_env.disable_block_gas_limit = false;
    cfg_env.disable_eip3607 = true;
    cfg_env.disable_base_fee = true;
    cfg_env.chain_id = 0;
    // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
    cfg_env.spec_id = revm::primitives::SpecId::SHANGHAI;
    cfg_env.perf_analyse_created_bytecodes = revm::primitives::AnalysisKind::Analyse;
    cfg_env.limit_contract_code_size = None;
    cfg_env
}

// modified from: https://github.com/paradigmxyz/reth/blob/cc576bc8690a3e16e6e5bf1cbbbfdd029e85e3d4/crates/rpc/rpc/src/eth/api/transactions.rs#L849
pub(crate) fn build_rpc_receipt(
    block: &SealedBlock,
    tx: TransactionSignedAndRecovered,
    tx_number: u64,
    receipt: Receipt,
) -> reth_rpc_types::TransactionReceipt {
    let transaction: TransactionSignedEcRecovered = tx.into();
    let transaction_kind = transaction.kind();

    let transaction_hash = Some(transaction.hash);
    let transaction_index = tx_number - block.transactions.start;
    let block_hash = Some(block.header.hash);
    let block_number = Some(U256::from(block.header.number));

    reth_rpc_types::TransactionReceipt {
        transaction_hash,
        transaction_index: U64::from(transaction_index),
        block_hash,
        block_number,
        from: transaction.signer(),
        to: match transaction_kind {
            Create => None,
            Call(addr) => Some(*addr),
        },
        cumulative_gas_used: U256::from(receipt.receipt.cumulative_gas_used),
        gas_used: Some(U256::from(receipt.gas_used)),
        // EIP-4844 related
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        blob_gas_used: None,
        blob_gas_price: None,
        contract_address: match transaction_kind {
            Create => Some(create_address(transaction.signer(), transaction.nonce())),
            Call(_) => None,
        },
        effective_gas_price: U128::from(
            transaction.effective_gas_price(block.header.base_fee_per_gas),
        ),
        transaction_type: transaction.tx_type().into(),
        logs_bloom: receipt.receipt.bloom_slow(),
        status_code: if receipt.receipt.success {
            Some(U64::from(1))
        } else {
            Some(U64::from(0))
        },
        state_root: None, // Pre https://eips.ethereum.org/EIPS/eip-658 (pre-byzantium) and won't be used
        logs: receipt
            .receipt
            .logs
            .into_iter()
            .enumerate()
            .map(|(idx, log)| reth_rpc_types::Log {
                address: log.address,
                topics: log.topics,
                data: log.data,
                block_hash,
                block_number,
                transaction_hash,
                transaction_index: Some(U256::from(transaction_index)),
                log_index: Some(U256::from(receipt.log_index_start + idx as u64)),
                removed: false,
            })
            .collect(),
    }
}

fn map_out_of_gas_err<C: sov_modules_api::Context>(
    block_env: BlockEnv,
    mut tx_env: revm::primitives::TxEnv,
    cfg_env: revm::primitives::CfgEnv,
    db: EvmDb<'_, C>,
) -> EthApiError {
    let req_gas_limit = tx_env.gas_limit;
    tx_env.gas_limit = block_env.gas_limit;
    let res = executor::inspect(db, &block_env, tx_env, cfg_env).unwrap();
    match res.result {
        ExecutionResult::Success { .. } => {
            // transaction succeeded by manually increasing the gas limit to
            // highest, which means the caller lacks funds to pay for the tx
            RpcInvalidTransactionError::BasicOutOfGas(U256::from(req_gas_limit)).into()
        }
        ExecutionResult::Revert { output, .. } => {
            // reverted again after bumping the limit
            RpcInvalidTransactionError::Revert(RevertError::new(output)).into()
        }
        ExecutionResult::Halt { reason, .. } => RpcInvalidTransactionError::EvmHalt(reason).into(),
    }
}

fn convert_u256_to_u64(u256: reth_primitives::U256) -> Result<u64, TryFromSliceError> {
    let bytes: [u8; 32] = u256.to_be_bytes();
    let bytes: [u8; 8] = bytes[24..].try_into()?;
    Ok(u64::from_be_bytes(bytes))
}
