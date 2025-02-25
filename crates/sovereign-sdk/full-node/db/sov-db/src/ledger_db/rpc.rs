use alloy_primitives::U64;
use sov_rollup_interface::rpc::{
    sequencer_commitment_to_response, BatchProofResponse, LastVerifiedBatchProofResponse,
    LedgerRpcProvider, SequencerCommitmentResponse, SoftConfirmationIdentifier,
    SoftConfirmationResponse, VerifiedBatchProofResponse,
};

use crate::schema::tables::{
    CommitmentsByNumber, SlotByHash, SoftConfirmationByHash, SoftConfirmationByNumber,
    SoftConfirmationStatus, VerifiedBatchProofsBySlotNumber,
};
use crate::schema::types::{SlotNumber, SoftConfirmationNumber};

/// The maximum number of batches that can be requested in a single RPC range query
const MAX_BATCHES_PER_REQUEST: u64 = 20;
/// The maximum number of soft confirmations that can be requested in a single RPC range query
const MAX_SOFT_CONFIRMATIONS_PER_REQUEST: u64 = 20;

fn check_if_l2_block_pruned(ledger_db: &LedgerDB, l2_height: u64) -> Result<(), anyhow::Error> {
    let last_pruned_l2_height = ledger_db.get_last_pruned_l2_height()?;
    if let Some(last_pruned_l2_height) = last_pruned_l2_height {
        if l2_height <= last_pruned_l2_height {
            anyhow::bail!("Soft confirmation at height {} has been pruned.", l2_height);
        }
    }
    Ok(())
}

use super::{L2GenesisStateRoot, LedgerDB, ProofsBySlotNumberV2, SharedLedgerOps};

impl LedgerRpcProvider for LedgerDB {
    fn get_soft_confirmation(
        &self,
        batch_id: &SoftConfirmationIdentifier,
    ) -> Result<Option<SoftConfirmationResponse>, anyhow::Error> {
        let batch_num = self.resolve_soft_confirmation_identifier(batch_id)?;
        Ok(match batch_num {
            Some(num) => {
                check_if_l2_block_pruned(self, num.0)?;

                if let Some(stored_batch) = self.db.get::<SoftConfirmationByNumber>(&num)? {
                    Some(stored_batch.try_into()?)
                } else {
                    None
                }
            }
            None => None,
        })
    }

    fn get_soft_confirmation_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<SoftConfirmationResponse>, anyhow::Error> {
        self.get_soft_confirmation(&SoftConfirmationIdentifier::Hash(*hash))
    }

    fn get_soft_confirmation_by_number(
        &self,
        number: u64,
    ) -> Result<Option<SoftConfirmationResponse>, anyhow::Error> {
        self.get_soft_confirmation(&SoftConfirmationIdentifier::Number(number))
    }

    fn get_soft_confirmations(
        &self,
        soft_confirmation_ids: &[SoftConfirmationIdentifier],
    ) -> Result<Vec<Option<SoftConfirmationResponse>>, anyhow::Error> {
        anyhow::ensure!(
            soft_confirmation_ids.len() <= MAX_SOFT_CONFIRMATIONS_PER_REQUEST as usize,
            "requested too many soft confirmations. Requested: {}. Max: {}",
            soft_confirmation_ids.len(),
            MAX_BATCHES_PER_REQUEST
        );

        let mut out = Vec::with_capacity(soft_confirmation_ids.len());
        for soft_confirmation_id in soft_confirmation_ids {
            if let Some(soft_confirmation) = self.get_soft_confirmation(soft_confirmation_id)? {
                out.push(Some(soft_confirmation));
            } else {
                out.push(None);
            }
        }
        Ok(out)
    }

    fn get_soft_confirmations_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Option<SoftConfirmationResponse>>, anyhow::Error> {
        anyhow::ensure!(start <= end, "start must be <= end");
        anyhow::ensure!(
            end - start < MAX_BATCHES_PER_REQUEST,
            "requested batch range too large. Max: {}",
            MAX_BATCHES_PER_REQUEST
        );
        let ids: Vec<_> = (start..=end)
            .map(SoftConfirmationIdentifier::Number)
            .collect();
        self.get_soft_confirmations(&ids)
    }

    fn get_soft_confirmation_status(
        &self,
        l2_height: u64,
    ) -> Result<sov_rollup_interface::rpc::SoftConfirmationStatus, anyhow::Error> {
        check_if_l2_block_pruned(self, l2_height)?;

        if self
            .db
            .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(l2_height))
            .ok()
            .flatten()
            .is_none()
        {
            return Err(anyhow::anyhow!(
                "Soft confirmation at height {} not processed yet.",
                l2_height
            ));
        }

        let status = self
            .db
            .get::<SoftConfirmationStatus>(&SoftConfirmationNumber(l2_height))?;

        match status {
            Some(status) => Ok(status),
            None => Ok(sov_rollup_interface::rpc::SoftConfirmationStatus::Trusted),
        }
    }

    fn get_l2_genesis_state_root(&self) -> Result<Option<Vec<u8>>, anyhow::Error> {
        self.db.get::<L2GenesisStateRoot>(&())
    }

    fn get_slot_number_by_hash(&self, hash: [u8; 32]) -> Result<Option<u64>, anyhow::Error> {
        self.db.get::<SlotByHash>(&hash).map(|v| v.map(|a| a.0))
    }

    fn get_sequencer_commitments_on_slot_by_number(
        &self,
        height: u64,
    ) -> Result<Option<Vec<SequencerCommitmentResponse>>, anyhow::Error> {
        match self.db.get::<CommitmentsByNumber>(&SlotNumber(height))? {
            Some(commitments) => Ok(Some(
                commitments
                    .into_iter()
                    .map(|commitment| sequencer_commitment_to_response(commitment, height))
                    .collect(),
            )),
            None => Ok(None),
        }
    }

    fn get_last_scanned_l1_height(&self) -> Result<u64, anyhow::Error> {
        match SharedLedgerOps::get_last_scanned_l1_height(self)? {
            Some(height) => Ok(height.0),
            None => Ok(0),
        }
    }

    fn get_batch_proof_data_by_l1_height(
        &self,
        height: u64,
    ) -> Result<Option<Vec<BatchProofResponse>>, anyhow::Error> {
        match self.db.get::<ProofsBySlotNumberV2>(&SlotNumber(height))? {
            Some(stored_proofs) => Ok(Some(
                stored_proofs
                    .into_iter()
                    .map(BatchProofResponse::from)
                    .collect(),
            )),
            None => Ok(None),
        }
    }

    fn get_verified_proof_data_by_l1_height(
        &self,
        height: u64,
    ) -> Result<Option<Vec<VerifiedBatchProofResponse>>, anyhow::Error> {
        match self
            .db
            .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(height))?
        {
            Some(stored_proofs) => Ok(Some(
                stored_proofs
                    .into_iter()
                    .map(VerifiedBatchProofResponse::from)
                    .collect(),
            )),
            None => Ok(None),
        }
    }

    fn get_last_verified_batch_proof(
        &self,
    ) -> Result<Option<LastVerifiedBatchProofResponse>, anyhow::Error> {
        let mut iter = self.db.iter::<VerifiedBatchProofsBySlotNumber>()?;
        iter.seek_to_last();
        match iter.next() {
            Some(Ok(mut item)) => {
                let firsh_proof = item.value.swap_remove(0);
                Ok(Some(LastVerifiedBatchProofResponse {
                    proof: firsh_proof.into(),
                    l1_height: U64::from(item.key.0),
                }))
            }
            Some(Err(e)) => Err(e),
            _ => Ok(None),
        }
    }

    fn get_head_soft_confirmation(
        &self,
    ) -> Result<Option<SoftConfirmationResponse>, anyhow::Error> {
        let head_l2_height =
            Self::last_version_written(&self.db, SoftConfirmationByNumber)?.unwrap_or(0);

        if let Some(stored_soft_confirmation) = self
            .db
            .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(head_l2_height))?
        {
            return Ok(Some(stored_soft_confirmation.try_into()?));
        }
        Ok(None)
    }

    fn get_head_soft_confirmation_height(&self) -> Result<u64, anyhow::Error> {
        let head_l2_height =
            Self::last_version_written(&self.db, SoftConfirmationByNumber)?.unwrap_or(0);
        Ok(head_l2_height)
    }
}

impl LedgerDB {
    fn resolve_soft_confirmation_identifier(
        &self,
        batch_id: &SoftConfirmationIdentifier,
    ) -> Result<Option<SoftConfirmationNumber>, anyhow::Error> {
        match batch_id {
            SoftConfirmationIdentifier::Hash(hash) => self.db.get::<SoftConfirmationByHash>(hash),
            SoftConfirmationIdentifier::Number(num) => Ok(Some(SoftConfirmationNumber(*num))),
        }
    }
}
