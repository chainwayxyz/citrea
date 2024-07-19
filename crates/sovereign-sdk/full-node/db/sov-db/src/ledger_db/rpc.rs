use serde::de::DeserializeOwned;
use sov_rollup_interface::rpc::{
    sequencer_commitment_to_response, BatchIdAndOffset, BatchIdentifier, BatchResponse,
    EventIdentifier, ItemOrHash, LastVerifiedProofResponse, LedgerRpcProvider, ProofResponse,
    QueryMode, SequencerCommitmentResponse, SlotIdAndOffset, SlotIdentifier, SlotResponse,
    SoftBatchIdentifier, SoftBatchResponse, TxIdAndOffset, TxIdentifier, TxResponse,
    VerifiedProofResponse,
};
use sov_rollup_interface::stf::Event;

use crate::schema::tables::{
    BatchByHash, BatchByNumber, CommitmentsByNumber, EventByNumber, ProofBySlotNumber, SlotByHash,
    SlotByNumber, SoftBatchByHash, SoftBatchByNumber, SoftConfirmationStatus, TxByHash, TxByNumber,
    VerifiedProofsBySlotNumber,
};
use crate::schema::types::{
    BatchNumber, EventNumber, SlotNumber, StoredBatch, StoredSlot, TxNumber,
};

/// The maximum number of batches that can be requested in a single RPC range query
const MAX_BATCHES_PER_REQUEST: u64 = 20;
/// The maximum number of soft batches that can be requested in a single RPC range query
const MAX_SOFT_BATCHES_PER_REQUEST: u64 = 20;
/// The maximum number of events that can be requested in a single RPC range query
const MAX_EVENTS_PER_REQUEST: u64 = 500;

use super::LedgerDB;

impl LedgerRpcProvider for LedgerDB {
    fn get_soft_batch(
        &self,
        batch_id: &SoftBatchIdentifier,
    ) -> Result<Option<SoftBatchResponse>, anyhow::Error> {
        let batch_num = self.resolve_soft_batch_identifier(batch_id)?;
        Ok(match batch_num {
            Some(num) => {
                if let Some(stored_batch) = self.db.get::<SoftBatchByNumber>(&num)? {
                    Some(stored_batch.try_into()?)
                } else {
                    None
                }
            }
            None => None,
        })
    }

    fn get_events(
        &self,
        event_ids: &[sov_rollup_interface::rpc::EventIdentifier],
    ) -> Result<Vec<Option<Event>>, anyhow::Error> {
        anyhow::ensure!(
            event_ids.len() <= MAX_EVENTS_PER_REQUEST as usize,
            "requested too many events. Requested: {}. Max: {}",
            event_ids.len(),
            MAX_EVENTS_PER_REQUEST
        );
        // TODO: Sort the input and use an iterator instead of querying for each slot individually
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/191
        let mut out = Vec::with_capacity(event_ids.len());
        for id in event_ids {
            let num = self.resolve_event_identifier(id)?;
            out.push(match num {
                Some(num) => self.db.get::<EventByNumber>(&num)?,
                None => None,
            })
        }
        Ok(out)
    }

    fn get_soft_batch_by_hash<T: DeserializeOwned>(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<SoftBatchResponse>, anyhow::Error> {
        self.get_soft_batch(&SoftBatchIdentifier::Hash(*hash))
    }

    fn get_soft_batch_by_number<T: DeserializeOwned>(
        &self,
        number: u64,
    ) -> Result<Option<SoftBatchResponse>, anyhow::Error> {
        self.get_soft_batch(&SoftBatchIdentifier::Number(number))
    }

    fn get_event_by_number(&self, number: u64) -> Result<Option<Event>, anyhow::Error> {
        self.get_events(&[EventIdentifier::Number(number)])
            .map(|mut events| events.pop().unwrap_or(None))
    }

    fn get_soft_batches(
        &self,
        soft_batch_ids: &[SoftBatchIdentifier],
    ) -> Result<Vec<Option<SoftBatchResponse>>, anyhow::Error> {
        anyhow::ensure!(
            soft_batch_ids.len() <= MAX_SOFT_BATCHES_PER_REQUEST as usize,
            "requested too many soft batches. Requested: {}. Max: {}",
            soft_batch_ids.len(),
            MAX_BATCHES_PER_REQUEST
        );

        let mut out = Vec::with_capacity(soft_batch_ids.len());
        for soft_batch_id in soft_batch_ids {
            if let Some(soft_batch) = self.get_soft_batch(soft_batch_id)? {
                out.push(Some(soft_batch));
            } else {
                out.push(None);
            }
        }
        Ok(out)
    }

    fn get_soft_batches_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Option<SoftBatchResponse>>, anyhow::Error> {
        anyhow::ensure!(start <= end, "start must be <= end");
        anyhow::ensure!(
            end - start < MAX_BATCHES_PER_REQUEST,
            "requested batch range too large. Max: {}",
            MAX_BATCHES_PER_REQUEST
        );
        let ids: Vec<_> = (start..=end).map(SoftBatchIdentifier::Number).collect();
        self.get_soft_batches(&ids)
    }

    fn get_soft_confirmation_status(
        &self,
        l2_height: u64,
    ) -> Result<sov_rollup_interface::rpc::SoftConfirmationStatus, anyhow::Error> {
        if self
            .db
            .get::<SoftBatchByNumber>(&BatchNumber(l2_height))
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

    fn get_prover_last_scanned_l1_height(&self) -> Result<u64, anyhow::Error> {
        match self.get_prover_last_scanned_l1_height()? {
            Some(height) => Ok(height.0),
            None => Ok(0),
        }
    }

    fn get_proof_data_by_l1_height(
        &self,
        height: u64,
    ) -> Result<Option<ProofResponse>, anyhow::Error> {
        match self.db.get::<ProofBySlotNumber>(&SlotNumber(height))? {
            Some(stored_proof) => Ok(Some(ProofResponse::from(stored_proof))),
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

    fn get_head_soft_batch(&self) -> Result<Option<SoftBatchResponse>, anyhow::Error> {
        let next_ids = self.get_next_items_numbers();

        if let Some(stored_soft_batch) = self
            .db
            .get::<SoftBatchByNumber>(&BatchNumber(next_ids.soft_batch_number.saturating_sub(1)))?
        {
            return Ok(Some(stored_soft_batch.try_into()?));
        }
        Ok(None)
    }

    fn get_head_soft_batch_height(&self) -> Result<u64, anyhow::Error> {
        let next_ids = self.get_next_items_numbers();
        Ok(next_ids.soft_batch_number.saturating_sub(1))
    }
}

impl LedgerDB {
    fn resolve_slot_identifier(
        &self,
        slot_id: &SlotIdentifier,
    ) -> Result<Option<SlotNumber>, anyhow::Error> {
        match slot_id {
            SlotIdentifier::Hash(hash) => self.db.get::<SlotByHash>(hash),
            SlotIdentifier::Number(num) => Ok(Some(SlotNumber(*num))),
        }
    }

    fn resolve_soft_batch_identifier(
        &self,
        batch_id: &SoftBatchIdentifier,
    ) -> Result<Option<BatchNumber>, anyhow::Error> {
        match batch_id {
            SoftBatchIdentifier::Hash(hash) => self.db.get::<SoftBatchByHash>(hash),
            SoftBatchIdentifier::Number(num) => Ok(Some(BatchNumber(*num))),
        }
    }

    fn resolve_batch_identifier(
        &self,
        batch_id: &BatchIdentifier,
    ) -> Result<Option<BatchNumber>, anyhow::Error> {
        match batch_id {
            BatchIdentifier::Hash(hash) => self.db.get::<BatchByHash>(hash),
            BatchIdentifier::Number(num) => Ok(Some(BatchNumber(*num))),
            BatchIdentifier::SlotIdAndOffset(SlotIdAndOffset { slot_id, offset }) => {
                if let Some(slot_num) = self.resolve_slot_identifier(slot_id)? {
                    Ok(self
                        .db
                        .get::<SlotByNumber>(&slot_num)?
                        .map(|slot: StoredSlot| BatchNumber(slot.batches.start.0 + offset)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn resolve_tx_identifier(
        &self,
        tx_id: &TxIdentifier,
    ) -> Result<Option<TxNumber>, anyhow::Error> {
        match tx_id {
            TxIdentifier::Hash(hash) => self.db.get::<TxByHash>(hash),
            TxIdentifier::Number(num) => Ok(Some(TxNumber(*num))),
            TxIdentifier::BatchIdAndOffset(BatchIdAndOffset { batch_id, offset }) => {
                if let Some(batch_num) = self.resolve_batch_identifier(batch_id)? {
                    Ok(self
                        .db
                        .get::<BatchByNumber>(&batch_num)?
                        .map(|batch: StoredBatch| TxNumber(batch.txs.start.0 + offset)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn resolve_event_identifier(
        &self,
        event_id: &EventIdentifier,
    ) -> Result<Option<EventNumber>, anyhow::Error> {
        match event_id {
            EventIdentifier::TxIdAndOffset(TxIdAndOffset { tx_id, offset }) => {
                if let Some(tx_num) = self.resolve_tx_identifier(tx_id)? {
                    Ok(self
                        .db
                        .get::<TxByNumber>(&tx_num)?
                        .map(|tx| EventNumber(tx.events.start.0 + offset)))
                } else {
                    Ok(None)
                }
            }
            EventIdentifier::Number(num) => Ok(Some(EventNumber(*num))),
            EventIdentifier::TxIdAndKey(_) => todo!(),
        }
    }
}
