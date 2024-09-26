use serde::de::DeserializeOwned;
use sov_rollup_interface::rpc::{
    sequencer_commitment_to_response, LastVerifiedProofResponse, LedgerRpcProvider, ProofResponse,
    SequencerCommitmentResponse, SoftConfirmationIdentifier, SoftConfirmationResponse,
    VerifiedProofResponse,
};

use crate::schema::tables::{
    CommitmentsByNumber, ProofsBySlotNumber, SlotByHash, SoftConfirmationByHash,
    SoftConfirmationByNumber, SoftConfirmationStatus, VerifiedProofsBySlotNumber,
};
use crate::schema::types::{BatchNumber, SlotNumber};

/// The maximum number of batches that can be requested in a single RPC range query
const MAX_BATCHES_PER_REQUEST: u64 = 20;
/// The maximum number of soft confirmations that can be requested in a single RPC range query
const MAX_SOFT_CONFIRMATIONS_PER_REQUEST: u64 = 20;

use super::{LedgerDB, SharedLedgerOps};

impl LedgerRpcProvider for LedgerDB {
    fn get_soft_confirmation(
        &self,
        batch_id: &SoftConfirmationIdentifier,
    ) -> Result<Option<SoftConfirmationResponse>, anyhow::Error> {
        let batch_num = self.resolve_soft_confirmation_identifier(batch_id)?;
        Ok(match batch_num {
            Some(num) => {
                if let Some(stored_batch) = self.db.get::<SoftConfirmationByNumber>(&num)? {
                    Some(stored_batch.try_into()?)
                } else {
                    None
                }
            }
            None => None,
        })
    }

    fn get_soft_confirmation_by_hash<T: DeserializeOwned>(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<SoftConfirmationResponse>, anyhow::Error> {
        self.get_soft_confirmation(&SoftConfirmationIdentifier::Hash(*hash))
    }

    fn get_soft_confirmation_by_number<T: DeserializeOwned>(
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
        if self
            .db
            .get::<SoftConfirmationByNumber>(&BatchNumber(l2_height))
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
            .get::<SoftConfirmationStatus>(&BatchNumber(l2_height))?;

        match status {
            Some(status) => Ok(status),
            None => Ok(sov_rollup_interface::rpc::SoftConfirmationStatus::Trusted),
        }
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

    fn get_proof_data_by_l1_height(
        &self,
        height: u64,
    ) -> Result<Option<Vec<ProofResponse>>, anyhow::Error> {
        match self.db.get::<ProofsBySlotNumber>(&SlotNumber(height))? {
            Some(stored_proofs) => Ok(Some(
                stored_proofs.into_iter().map(ProofResponse::from).collect(),
            )),
            None => Ok(None),
        }
    }

    fn get_verified_proof_data_by_l1_height(
        &self,
        height: u64,
    ) -> Result<Option<Vec<VerifiedProofResponse>>, anyhow::Error> {
        match self
            .db
            .get::<VerifiedProofsBySlotNumber>(&SlotNumber(height))?
        {
            Some(stored_proofs) => Ok(Some(
                stored_proofs
                    .into_iter()
                    .map(VerifiedProofResponse::from)
                    .collect(),
            )),
            None => Ok(None),
        }
    }

    fn get_last_verified_proof(&self) -> Result<Option<LastVerifiedProofResponse>, anyhow::Error> {
        let mut iter = self.db.iter::<VerifiedProofsBySlotNumber>()?;
        iter.seek_to_last();
        match iter.next() {
            Some(Ok(item)) => Ok(Some(LastVerifiedProofResponse {
                proof: item.value[0].clone().into(),
                height: item.key.0,
            })),
            Some(Err(e)) => Err(e),
            _ => Ok(None),
        }
    }

    fn get_head_soft_confirmation(
        &self,
    ) -> Result<Option<SoftConfirmationResponse>, anyhow::Error> {
        let next_ids = self.get_next_items_numbers();

        if let Some(stored_soft_confirmation) = self.db.get::<SoftConfirmationByNumber>(
            &BatchNumber(next_ids.soft_confirmation_number.saturating_sub(1)),
        )? {
            return Ok(Some(stored_soft_confirmation.try_into()?));
        }
        Ok(None)
    }

    fn get_head_soft_confirmation_height(&self) -> Result<u64, anyhow::Error> {
        let next_ids = self.get_next_items_numbers();
        Ok(next_ids.soft_confirmation_number.saturating_sub(1))
    }
}

impl LedgerDB {
    fn resolve_soft_confirmation_identifier(
        &self,
        batch_id: &SoftConfirmationIdentifier,
    ) -> Result<Option<BatchNumber>, anyhow::Error> {
        match batch_id {
            SoftConfirmationIdentifier::Hash(hash) => self.db.get::<SoftConfirmationByHash>(hash),
            SoftConfirmationIdentifier::Number(num) => Ok(Some(BatchNumber(*num))),
        }
    }
}
