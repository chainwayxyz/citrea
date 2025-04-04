//! A JSON-RPC server implementation for any [`LedgerRpcProvider`].

use alloy_primitives::{U32, U64};
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::rpc::{
    BatchProofResponse, L2BlockStatus, LastVerifiedBatchProofResponse, LedgerRpcProvider,
    SequencerCommitmentResponse, VerifiedBatchProofResponse,
};

use crate::{HexHash, HexStateRoot, LedgerRpcServer};

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
    fn get_l2_block_by_number(&self, number: U64) -> RpcResult<Option<L2BlockResponse>> {
        self.ledger
            .get_l2_block_by_number(number.to())
            .map_err(to_ledger_rpc_error)
    }

    fn get_l2_block_by_hash(&self, hash: HexHash) -> RpcResult<Option<L2BlockResponse>> {
        self.ledger
            .get_l2_block_by_hash(&hash.0)
            .map_err(to_ledger_rpc_error)
    }

    fn get_l2_block_range(&self, start: U64, end: U64) -> RpcResult<Vec<Option<L2BlockResponse>>> {
        self.ledger
            .get_l2_blocks_range(start.to(), end.to())
            .map_err(to_ledger_rpc_error)
    }

    fn get_l2_block_status(&self, l2_block_receipt: U64) -> RpcResult<L2BlockStatus> {
        self.ledger
            .get_l2_block_status(l2_block_receipt.to())
            .map_err(to_ledger_rpc_error)
    }

    fn get_l2_genesis_state_root(&self) -> RpcResult<Option<HexStateRoot>> {
        self.ledger
            .get_l2_genesis_state_root()
            .map(|v| v.map(HexStateRoot))
            .map_err(to_ledger_rpc_error)
    }

    fn get_last_scanned_l1_height(&self) -> RpcResult<U64> {
        self.ledger
            .get_last_scanned_l1_height()
            .map(U64::from)
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

    fn get_head_l2_block(&self) -> RpcResult<Option<L2BlockResponse>> {
        self.ledger.get_head_l2_block().map_err(to_ledger_rpc_error)
    }

    fn get_head_l2_block_height(&self) -> RpcResult<U64> {
        self.ledger
            .get_head_l2_block_height()
            .map(U64::from)
            .map_err(to_ledger_rpc_error)
    }

    fn get_sequencer_commitment_by_index(
        &self,
        index: U32,
    ) -> RpcResult<Option<SequencerCommitmentResponse>> {
        self.ledger
            .get_sequencer_commitment_by_index(index.to())
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
