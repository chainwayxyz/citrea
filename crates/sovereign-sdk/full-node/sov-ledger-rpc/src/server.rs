//! A JSON-RPC server implementation for any [`LedgerRpcProvider`].

use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use reth_primitives::U64;
use serde::de::DeserializeOwned;
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_rollup_interface::rpc::LedgerRpcProvider;

use crate::HexHash;

const LEDGER_RPC_ERROR: &str = "LEDGER_RPC_ERROR";

fn to_ledger_rpc_error(err: impl ToString) -> ErrorObjectOwned {
    to_jsonrpsee_error_object(LEDGER_RPC_ERROR, err)
}

/// Creates a new [`jsonrpsee::RpcModule`] that exposes all JSON-RPC methods
/// necessary to interface with the [`LedgerRpcProvider`].
pub fn rpc_module<T, B, Tx>(ledger: T) -> anyhow::Result<RpcModule<T>>
where
    T: LedgerRpcProvider + Send + Sync + 'static,
    B: serde::Serialize + DeserializeOwned + Clone + 'static,
    Tx: serde::Serialize + DeserializeOwned + Clone + 'static,
{
    let mut rpc = RpcModule::new(ledger);

    rpc.register_blocking_method(
        "ledger_getSoftConfirmationByHash",
        move |params, ledger, _| {
            let args: HexHash = params.one()?;
            ledger
                .get_soft_confirmation_by_hash::<Tx>(&args.0)
                .map_err(to_ledger_rpc_error)
        },
    )?;
    rpc.register_blocking_method(
        "ledger_getSoftConfirmationByNumber",
        move |params, ledger, _| {
            let args: U64 = params.one()?;

            ledger
                .get_soft_confirmation_by_number::<Tx>(args.to())
                .map_err(to_ledger_rpc_error)
        },
    )?;
    rpc.register_blocking_method(
        "ledger_getSoftConfirmationRange",
        move |params, ledger, _| {
            let args: (U64, U64) = params.parse()?;
            ledger
                .get_soft_confirmations_range(args.0.to(), args.1.to())
                .map_err(to_ledger_rpc_error)
        },
    )?;
    rpc.register_blocking_method(
        "ledger_getSoftConfirmationStatus",
        move |params, ledger, _| {
            let args: U64 = params.one()?;
            ledger
                .get_soft_confirmation_status(args.to())
                .map_err(to_ledger_rpc_error)
        },
    )?;
    rpc.register_blocking_method("ledger_getL2GenesisStateRoot", move |_, ledger, _| {
        ledger
            .get_l2_genesis_state_root()
            .map_err(to_ledger_rpc_error)
    })?;
    rpc.register_blocking_method("ledger_getLastScannedL1Height", move |_, ledger, _| {
        ledger
            .get_last_scanned_l1_height()
            .map_err(to_ledger_rpc_error)
    })?;

    rpc.register_blocking_method(
        "ledger_getSequencerCommitmentsOnSlotByNumber",
        move |params, ledger, _| {
            // Returns commitments on DA slot with given height.
            let height: U64 = params.one()?;

            ledger
                .get_sequencer_commitments_on_slot_by_number(height.to())
                .map_err(to_ledger_rpc_error)
        },
    )?;

    rpc.register_blocking_method(
        "ledger_getSequencerCommitmentsOnSlotByHash",
        move |params, ledger, _| {
            // Returns commitments on DA slot with given hash.
            let hash: HexHash = params.one()?;
            let Some(height) = ledger
                .get_slot_number_by_hash(hash.0)
                .map_err(to_ledger_rpc_error)?
            else {
                return Ok(None);
            };

            ledger
                .get_sequencer_commitments_on_slot_by_number(height)
                .map_err(to_ledger_rpc_error)
        },
    )?;

    rpc.register_blocking_method(
        "ledger_getBatchProofsBySlotHeight",
        move |params, ledger, _| {
            // Returns proof on DA slot with given height
            let height: U64 = params.one()?;
            ledger
                .get_batch_proof_data_by_l1_height(height.to())
                .map_err(to_ledger_rpc_error)
        },
    )?;

    rpc.register_blocking_method(
        "ledger_getBatchProofsBySlotHash",
        move |params, ledger, _| {
            // Returns proof on DA slot with given height
            let hash: HexHash = params.one()?;
            let Some(height) = ledger
                .get_slot_number_by_hash(hash.0)
                .map_err(to_ledger_rpc_error)?
            else {
                return Ok(None);
            };

            ledger
                .get_batch_proof_data_by_l1_height(height)
                .map_err(to_ledger_rpc_error)
        },
    )?;

    rpc.register_blocking_method(
        "ledger_getVerifiedBatchProofsBySlotHeight",
        move |params, ledger, _| {
            // Returns proof on DA slot with given height
            let height: U64 = params.one()?;
            ledger
                .get_verified_proof_data_by_l1_height(height.to())
                .map_err(to_ledger_rpc_error)
        },
    )?;

    rpc.register_blocking_method("ledger_getLastVerifiedBatchProof", move |_, ledger, _| {
        // Returns latest proof data
        ledger
            .get_last_verified_batch_proof()
            .map_err(to_ledger_rpc_error)
    })?;

    rpc.register_blocking_method("ledger_getHeadSoftConfirmation", move |_, ledger, _| {
        ledger
            .get_head_soft_confirmation()
            .map_err(to_ledger_rpc_error)
    })?;

    rpc.register_blocking_method(
        "ledger_getHeadSoftConfirmationHeight",
        move |_, ledger, _| {
            ledger
                .get_head_soft_confirmation_height()
                .map_err(to_ledger_rpc_error)
        },
    )?;

    Ok(rpc)
}
