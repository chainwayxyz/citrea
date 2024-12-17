//! A JSON-RPC server implementation for any [`LedgerRpcProvider`].

use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use reth_primitives::U64;
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_rollup_interface::rpc::{
    BatchProofResponse, LastVerifiedBatchProofResponse, LedgerRpcProvider,
    SequencerCommitmentResponse, SoftConfirmationResponse, SoftConfirmationStatus,
    VerifiedBatchProofResponse,
};

use crate::{HexHash, LedgerRpcServer};

const LEDGER_RPC_ERROR: &str = "LEDGER_RPC_ERROR";

fn to_ledger_rpc_error(err: impl ToString) -> ErrorObjectOwned {
    to_jsonrpsee_error_object(LEDGER_RPC_ERROR, err)
}
pub struct LedgerRpcServerImpl<T> {
    ledger: T,
}

impl<T> LedgerRpcServerImpl<T> {
    pub fn new(ledger: T) -> Self {
        Self { ledger }
    }
}

impl<T> LedgerRpcServer for LedgerRpcServerImpl<T>
where
    T: LedgerRpcProvider + Send + Sync + 'static,
{
    fn get_soft_confirmation_by_number(
        &self,
        number: U64,
    ) -> RpcResult<Option<SoftConfirmationResponse>> {
        self.ledger
            .get_soft_confirmation_by_number(number.to())
            .map_err(to_ledger_rpc_error)
    }

    fn get_soft_confirmation_by_hash(
        &self,
        hash: HexHash,
    ) -> RpcResult<Option<SoftConfirmationResponse>> {
        self.ledger
            .get_soft_confirmation_by_hash(&hash.0)
            .map_err(to_ledger_rpc_error)
    }

    fn get_soft_confirmation_range(
        &self,
        start: U64,
        end: U64,
    ) -> RpcResult<Vec<Option<SoftConfirmationResponse>>> {
        self.ledger
            .get_soft_confirmations_range(start.to(), end.to())
            .map_err(to_ledger_rpc_error)
    }

    fn get_soft_confirmation_status(
        &self,
        soft_confirmation_receipt: U64,
    ) -> RpcResult<SoftConfirmationStatus> {
        self.ledger
            .get_soft_confirmation_status(soft_confirmation_receipt.to())
            .map_err(to_ledger_rpc_error)
    }

    fn get_l2_genesis_state_root(&self) -> RpcResult<Option<Vec<u8>>> {
        self.ledger
            .get_l2_genesis_state_root()
            .map_err(to_ledger_rpc_error)
    }

    fn get_last_scanned_l1_height(&self) -> RpcResult<u64> {
        self.ledger
            .get_last_scanned_l1_height()
            .map_err(to_ledger_rpc_error)
    }

    fn get_sequencer_commitments_on_slot_by_number(
        &self,
        height: U64,
    ) -> RpcResult<Option<Vec<SequencerCommitmentResponse>>> {
        self.ledger
            .get_sequencer_commitments_on_slot_by_number(height.to())
            .map_err(to_ledger_rpc_error)
    }

    fn get_sequencer_commitments_on_slot_by_hash(
        &self,
        hash: HexHash,
    ) -> RpcResult<Option<Vec<SequencerCommitmentResponse>>> {
        let Some(height) = self
            .ledger
            .get_slot_number_by_hash(hash.0)
            .map_err(to_ledger_rpc_error)?
        else {
            return Ok(None);
        };

        self.ledger
            .get_sequencer_commitments_on_slot_by_number(height)
            .map_err(to_ledger_rpc_error)
    }

    fn get_batch_proofs_by_slot_height(
        &self,
        height: U64,
    ) -> RpcResult<Option<Vec<BatchProofResponse>>> {
        self.ledger
            .get_batch_proof_data_by_l1_height(height.to())
            .map_err(to_ledger_rpc_error)
    }

    fn get_batch_proofs_by_slot_hash(
        &self,
        hash: HexHash,
    ) -> RpcResult<Option<Vec<BatchProofResponse>>> {
        let Some(height) = self
            .ledger
            .get_slot_number_by_hash(hash.0)
            .map_err(to_ledger_rpc_error)?
        else {
            return Ok(None);
        };

        self.ledger
            .get_batch_proof_data_by_l1_height(height)
            .map_err(to_ledger_rpc_error)
    }

    fn get_verified_batch_proofs_by_slot_height(
        &self,
        height: U64,
    ) -> RpcResult<Option<Vec<VerifiedBatchProofResponse>>> {
        self.ledger
            .get_verified_proof_data_by_l1_height(height.to())
            .map_err(to_ledger_rpc_error)
    }

    fn get_last_verified_batch_proof(&self) -> RpcResult<Option<LastVerifiedBatchProofResponse>> {
        self.ledger
            .get_last_verified_batch_proof()
            .map_err(to_ledger_rpc_error)
    }

    fn get_head_soft_confirmation(&self) -> RpcResult<Option<SoftConfirmationResponse>> {
        self.ledger
            .get_head_soft_confirmation()
            .map_err(to_ledger_rpc_error)
    }

    fn get_head_soft_confirmation_height(&self) -> RpcResult<u64> {
        self.ledger
            .get_head_soft_confirmation_height()
            .map_err(to_ledger_rpc_error)
    }
}

pub fn create_rpc_module<T>(ledger: T) -> RpcModule<LedgerRpcServerImpl<T>>
where
    T: LedgerRpcProvider + Send + Sync + 'static,
{
    let server = LedgerRpcServerImpl::new(ledger);
    LedgerRpcServer::into_rpc(server)
}
