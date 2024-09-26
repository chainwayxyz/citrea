//! A JSON-RPC server implementation for any [`LedgerRpcProvider`].

use jsonrpsee::RpcModule;
use serde::de::DeserializeOwned;
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_rollup_interface::rpc::LedgerRpcProvider;

use crate::HexHash;

const LEDGER_RPC_ERROR: &str = "LEDGER_RPC_ERROR";

/// Creates a new [`jsonrpsee::RpcModule`] that exposes all JSON-RPC methods
/// necessary to interface with the [`LedgerRpcProvider`].
///
/// # Example
/// ```
/// use sov_ledger_rpc::server::rpc_module;
/// use tempfile::tempdir;
/// use sov_db::ledger_db::LedgerDB;
///
/// /// Creates a new [`LedgerDB`] and starts serving JSON-RPC requests.
/// async fn rpc_server() -> jsonrpsee::server::ServerHandle {
///     let dir = tempdir().unwrap();
///     let db = LedgerDB::with_path(dir).unwrap();
///     let rpc_module = rpc_module::<LedgerDB, u32, u32>(db).unwrap();
///
///     let server = jsonrpsee::server::ServerBuilder::default()
///         .build("127.0.0.1:0")
///         .await
///         .unwrap();
///     server.start(rpc_module)
/// }
/// ```
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
                .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
        },
    )?;
    rpc.register_blocking_method(
        "ledger_getSoftConfirmationByNumber",
        move |params, ledger, _| {
            let args: u64 = params.one()?;
            ledger
                .get_soft_confirmation_by_number::<Tx>(args)
                .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
        },
    )?;
    rpc.register_blocking_method(
        "ledger_getSoftConfirmationRange",
        move |params, ledger, _| {
            let args: (u64, u64) = params.parse()?;
            ledger
                .get_soft_confirmations_range(args.0, args.1)
                .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
        },
    )?;
    rpc.register_blocking_method(
        "ledger_getSoftConfirmationStatus",
        move |params, ledger, _| {
            let args: u64 = params.one()?;
            ledger
                .get_soft_confirmation_status(args)
                .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
        },
    )?;
    rpc.register_blocking_method("ledger_getLastScannedL1Hieght", move |_, ledger, _| {
        ledger
            .get_last_scanned_l1_height()
            .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
    })?;

    rpc.register_blocking_method(
        "ledger_getSequencerCommitmentsOnSlotByNumber",
        move |params, ledger, _| {
            // Returns commitments on DA slot with given height.
            let height: u64 = params.one()?;

            ledger
                .get_sequencer_commitments_on_slot_by_number(height)
                .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
        },
    )?;

    rpc.register_blocking_method(
        "ledger_getSequencerCommitmentsOnSlotByHash",
        move |params, ledger, _| {
            // Returns commitments on DA slot with given hash.
            let hash: [u8; 32] = params.one()?;
            let height = ledger
                .get_slot_number_by_hash(hash)
                .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))?;
            match height {
                Some(height) => ledger
                    .get_sequencer_commitments_on_slot_by_number(height)
                    .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e)),
                None => Ok(None),
            }
        },
    )?;

    rpc.register_blocking_method("ledger_getProofsBySlotHeight", move |params, ledger, _| {
        // Returns proof on DA slot with given height
        let height: u64 = params.one()?;
        ledger
            .get_proof_data_by_l1_height(height)
            .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
    })?;

    rpc.register_blocking_method("ledger_getProofsBySlotHash", move |params, ledger, _| {
        // Returns proof on DA slot with given height
        let hash: [u8; 32] = params.one()?;
        let height = ledger
            .get_slot_number_by_hash(hash)
            .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))?;
        match height {
            Some(height) => ledger
                .get_proof_data_by_l1_height(height)
                .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e)),
            None => Ok(None),
        }
    })?;

    rpc.register_blocking_method(
        "ledger_getVerifiedProofsBySlotHeight",
        move |params, ledger, _| {
            // Returns proof on DA slot with given height
            let height: u64 = params.one()?;
            ledger
                .get_verified_proof_data_by_l1_height(height)
                .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
        },
    )?;

    rpc.register_blocking_method("ledger_getLastVerifiedProof", move |_, ledger, _| {
        // Returns latest proof data
        ledger
            .get_last_verified_proof()
            .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
    })?;

    rpc.register_blocking_method("ledger_getHeadSoftConfirmation", move |_, ledger, _| {
        ledger
            .get_head_soft_confirmation()
            .map_err(|e: anyhow::Error| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
    })?;

    rpc.register_blocking_method(
        "ledger_getHeadSoftConfirmationHeight",
        move |_, ledger, _| {
            ledger
                .get_head_soft_confirmation_height()
                .map_err(|e| to_jsonrpsee_error_object(LEDGER_RPC_ERROR, e))
        },
    )?;

    Ok(rpc)
}
