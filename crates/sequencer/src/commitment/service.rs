use std::cmp;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use citrea_evm::{get_last_l1_height_in_light_client, Evm};
use citrea_primitives::forks::get_fork2_activation_height_non_zero;
use citrea_primitives::types::L2BlockHash;
use citrea_stf::runtime::DefaultContext;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::L2BlockNumber;
use sov_modules_api::WorkingSet;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::{BlockHeaderTrait, DaTxRequest, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, TxRequestWithNotifier};
use sov_state::ProverStorage;
use tokio::select;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument};

use super::controller::CommitmentController;
use super::helpers::load_next_commitment_index;
use crate::metrics::SEQUENCER_METRICS;

/// L2 heights to commit
pub(crate) type CommitmentRange = RangeInclusive<L2BlockNumber>;

pub struct CommitmentService<Da, Db>
where
    Da: DaService,
    Db: SequencerLedgerOps,
{
    ledger_db: Db,
    da_service: Arc<Da>,
    sequencer_da_pub_key: Vec<u8>,
    next_commitment_index: u32,
    commitment_controller: Option<CommitmentController<Db>>,
}

impl<Da, Db> CommitmentService<Da, Db>
where
    Da: DaService,
    Db: SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    pub fn new(
        ledger_db: Db,
        da_service: Arc<Da>,
        sequencer_da_pub_key: Vec<u8>,
        min_l2_blocks: u64,
    ) -> Self {
        let commitment_controller =
            Some(CommitmentController::new(ledger_db.clone(), min_l2_blocks));
        let next_commitment_index = load_next_commitment_index(&ledger_db);
        Self {
            ledger_db,
            da_service,
            sequencer_da_pub_key,
            next_commitment_index,
            commitment_controller,
        }
    }

    pub async fn run(
        mut self,
        storage_manager: ProverStorageManager,
        l2_block_hash: L2BlockHash,
        cancellation_token: CancellationToken,
    ) {
        if l2_block_hash != [0; 32] {
            let prestate = storage_manager.create_final_view_storage();
            let working_set = WorkingSet::new(prestate.clone());

            // Resubmit if there were pending commitments on restart, skip it on first init
            if let Err(e) = self.resubmit_pending_commitments(working_set).await {
                error!("Could not resubmit pending commitments: {:?}", e);
            }
        }

        let check_new_block_time = Duration::from_secs(2);
        let mut check_new_block_tick = tokio::time::interval(check_new_block_time);
        check_new_block_tick.tick().await;

        // Get latest finalized and pending commitments and find the max height
        let last_finalized_l2_height = match self.ledger_db.get_last_commitment() {
            Ok(seq) => seq
                .map(|seq| L2BlockNumber(seq.l2_end_block_number))
                .unwrap_or(L2BlockNumber(0)),
            Err(e) => {
                error!("Could not fetch last commitment: {:?}", e);
                return;
            }
        };
        let last_pending_l2_height = match self.ledger_db.get_pending_commitments() {
            Ok(commitments) => commitments
                .iter()
                .map(|seq| L2BlockNumber(seq.l2_end_block_number))
                .max()
                .unwrap_or(L2BlockNumber(0)),
            Err(e) => {
                error!("Could not read pending sequencer commitments: {:?}", e);
                return;
            }
        };
        let mut from_l2_height =
            L2BlockNumber(cmp::max(last_finalized_l2_height, last_pending_l2_height).0 + 1);

        let commitment_controller = Arc::new(
            self.commitment_controller
                .take()
                .expect("Commitment controller should be present"),
        );

        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                },
                _ = check_new_block_tick.tick() => {
                    let head_l2_height = match self.ledger_db.get_head_l2_block_height() {
                        Ok(head_l2_height) => L2BlockNumber(head_l2_height.unwrap_or(0)),
                        Err(e) => {
                            error!("Failed to fetch head L2 height: {:?}", e);
                            return;
                        }
                    };

                    // No need to check commitment criteria if the start L2 block number did not change.
                    if head_l2_height <= from_l2_height {
                        continue;
                    }

                    // Checking the possibility of a commitment up to the head block means that
                    // the state diff might have exceeded the limit by a significant portion and/or
                    // the max amount of blocks we commit for.
                    // Instead, we loop here from the last commitment height + 1 incrementally and commit
                    // as soon as we find a block which signals the possibility of a commitment.
                    for current_l2_height in from_l2_height.0..=head_l2_height.0 {
                        let cc = commitment_controller.clone();

                        let Ok(commitment_info) = tokio::task::spawn_blocking(move || {
                            cc.should_commit(from_l2_height, L2BlockNumber(current_l2_height))
                        }).await else {
                            error!("Failed to check commitment criteria");
                            continue;
                        };

                        let commitment_info = match commitment_info {
                            Ok(Some(commitment_info)) => {
                                commitment_info
                            },
                            Err(e) => {
                                error!("Error while checking commitment criteria: {:?}", e);
                                continue;
                            },
                            _ => {
                                continue;
                            }
                        };

                        commitment_controller.reset();
                        if let Err(e) = commitment_controller.clear_commitment_state_diffs(commitment_info.start().0..=commitment_info.end().0) {
                            error!("Could not clear commitment state diffs: {:?}", e);
                        }

                        let index = self.next_commitment_index;

                        from_l2_height = L2BlockNumber(commitment_info.end().0 + 1);

                        if let Err(e) = self.commit(index, &commitment_info).await {
                            error!("Could not submit commitment: {:?}", e);
                        }

                        // Stop and let the next tick start from the last set `from_l2_height`
                        break;
                    }
                },
            }
        }
    }

    pub async fn commit(
        &mut self,
        commitment_index: u32,
        commitment_info: &CommitmentRange,
    ) -> anyhow::Result<()> {
        let l2_start = *commitment_info.start();
        let l2_end = *commitment_info.end();

        let l2_block_hashes = self
            .ledger_db
            .get_l2_block_range(commitment_info)?
            .iter()
            .map(|sb| sb.hash)
            .collect::<Vec<[u8; 32]>>();

        SEQUENCER_METRICS
            .commitment_blocks_count
            .set(l2_block_hashes.len() as f64);

        let commitment = self.get_commitment(commitment_index, commitment_info, l2_block_hashes)?;

        debug!("Sequencer: submitting commitment: {:?}", commitment);

        let tx_request = DaTxRequest::SequencerCommitment(commitment.clone());
        let (notify, rx) = oneshot::channel();
        let request = TxRequestWithNotifier { tx_request, notify };
        self.da_service
            .get_send_transaction_queue()
            .send(request)
            .map_err(|_| anyhow!("Bitcoin service already stopped!"))?;

        info!(
            "Sent commitment to DA queue. L2 range: #{}-{}, index: {}",
            l2_start.0, l2_end.0, commitment_index,
        );

        let start = Instant::now();
        let ledger_db = self.ledger_db.clone();

        // Even though the commitment service does not shutdown before we get a response from the DA service,
        // we still need to store the commitment in the pending commitments, so that if anything happens
        // from the time we send the tx to the DA service and until we get a response (so the tx wasn't even submitted yet),
        // e.g. server shutdown, we can resubmit the pending commitments.
        //
        // So pending status for a commitment spans from da service submission to entrance to mempool.
        ledger_db.put_pending_commitment(&commitment).map_err(|_| {
            anyhow!("Sequencer: Failed to store sequencer commitment in pending commitments")
        })?;

        let _tx_id = rx
            .await
            .map_err(|_| anyhow!("DA service is dead!"))?
            .map_err(|_| anyhow!("Send transaction cannot fail"))?;

        SEQUENCER_METRICS.send_commitment_execution.record(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );

        ledger_db
            .put_commitment_by_index(&commitment)
            .map_err(|_| anyhow!("Sequencer: Failed to store sequencer commitment by index"))?;

        ledger_db.delete_pending_commitment(commitment.index)?;

        // Increment the next commitment index here knowing that it completed successfully.
        self.next_commitment_index += 1;

        info!("New commitment. L2 range: #{}-{}", l2_start.0, l2_end.0);

        Ok(())
    }

    #[instrument(level = "trace", skip(self, working_set), err, ret)]
    pub async fn resubmit_pending_commitments(
        &mut self,
        mut working_set: WorkingSet<ProverStorage>,
    ) -> anyhow::Result<()> {
        info!("Resubmitting pending commitments");

        let mut pending_db_commitments = self.ledger_db.get_pending_commitments()?;
        pending_db_commitments.sort();
        info!("Pending db commitments: {:?}", pending_db_commitments);

        let mut pending_mempool_commitments = self.get_pending_mempool_commitments().await;
        pending_mempool_commitments.sort();
        info!(
            "Commitments that are already in DA mempool: {:?}",
            pending_mempool_commitments
        );

        // to determine which L1 block to start scanning from
        let start_scanning_l1_from: u64 = {
            let l2_height = self
                .ledger_db
                .get_last_commitment()?
                .map(|c| c.l2_end_block_number)
                .unwrap_or(1);

            // set state to end of evm block l2_height
            working_set.set_archival_version(l2_height + 1);

            let l1_height = get_last_l1_height_in_light_client(
                &Evm::<DefaultContext>::default(),
                &mut working_set,
            )
            .expect("There must be a last l1 height");

            l1_height.to::<u64>() + 1
        };

        let mut mined_commitments = self
            .get_mined_commitments_from(start_scanning_l1_from)
            .await?;
        mined_commitments.sort();
        info!(
            "Commitments that are already mined by DA: {:?}",
            mined_commitments
        );

        let mut pending_commitments_to_remove = vec![];
        pending_commitments_to_remove.extend(pending_mempool_commitments);
        pending_commitments_to_remove.extend(mined_commitments);

        pending_commitments_to_remove.sort();
        pending_commitments_to_remove.dedup();
        info!(
            "Pending commitments to remove: {:?}",
            pending_commitments_to_remove
        );

        for pending_db_comm in pending_db_commitments {
            if pending_commitments_to_remove
                .iter()
                .any(|commitment| commitment.index == pending_db_comm.index)
            {
                // this pending commitment is either mined or in the L1 mempool
                // so we can delete it from the pending db and put it to commitment by index
                self.ledger_db.put_commitment_by_index(&pending_db_comm)?;
                self.ledger_db
                    .delete_pending_commitment(pending_db_comm.index)?;
            } else {
                // Submit commitment
                let l2_start_block_number = if pending_db_comm.index == 1 {
                    get_fork2_activation_height_non_zero()
                } else {
                    self.ledger_db
                        .get_commitment_by_index(pending_db_comm.index - 1)?
                        .unwrap()
                        .l2_end_block_number
                        + 1
                };
                let range = L2BlockNumber(l2_start_block_number)
                    ..=L2BlockNumber(pending_db_comm.l2_end_block_number);

                self.commit(pending_db_comm.index, &range).await?;
            }
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub fn get_commitment(
        &self,
        commitment_index: u32,
        commitment_info: &CommitmentRange,
        l2_block_hashes: Vec<[u8; 32]>,
    ) -> anyhow::Result<SequencerCommitment> {
        // sanity check
        assert_eq!(
            commitment_info.end().0 - commitment_info.start().0 + 1u64,
            l2_block_hashes.len() as u64,
            "Sequencer: Soft confirmation hashes length does not match the commitment info"
        );
        // build merkle tree over soft confirmations
        let merkle_root = MerkleTree::<Sha256>::from_leaves(l2_block_hashes.as_slice())
            .root()
            .ok_or(anyhow!("Couldn't compute merkle root"))?;
        Ok(SequencerCommitment {
            merkle_root,
            index: commitment_index,
            l2_end_block_number: commitment_info.end().0,
        })
    }

    async fn get_pending_mempool_commitments(&self) -> Vec<SequencerCommitment> {
        self.da_service
            .get_pending_sequencer_commitments(&self.sequencer_da_pub_key)
            .await
    }

    async fn get_mined_commitments_from(
        &self,
        start_height: u64,
    ) -> anyhow::Result<Vec<SequencerCommitment>> {
        info!(
            "Getting mined commitments from DA service starting from height: {}",
            start_height
        );

        let head_da_height = self
            .da_service
            .get_head_block_header()
            .await
            .map_err(|e| anyhow!(e))?
            .height();
        let mut mined_commitments = vec![];

        for height in start_height..=head_da_height {
            let block = self
                .da_service
                .get_block_at(height)
                .await
                .map_err(|e| anyhow!(e))?;
            let iter = self
                .da_service
                .extract_relevant_sequencer_commitments(&block, &self.sequencer_da_pub_key)
                .into_iter()
                .map(|(_, commitment)| commitment);
            mined_commitments.extend(iter);
        }

        Ok(mined_commitments)
    }
}
