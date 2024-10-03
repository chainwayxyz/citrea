use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use borsh::BorshDeserialize;
use pin_project::pin_project;
use sha2::Digest;
use sov_rollup_interface::da::{
    BlobReaderTrait, BlockHeaderTrait, DaData, DaDataBatchProof, DaDataLightClient, DaSpec, Time,
};
use sov_rollup_interface::services::da::{DaService, SenderWithNotifier, SlotData};
use sov_rollup_interface::zk::Proof;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{broadcast, Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use tokio::{select, time};
use tokio_util::sync::CancellationToken;

use crate::db_connector::DbConnector;
use crate::types::{MockAddress, MockBlob, MockBlock, MockDaVerifier};
use crate::verifier::MockDaSpec;
use crate::{MockBlockHeader, MockHash};

const GENESIS_HEADER: MockBlockHeader = MockBlockHeader {
    prev_hash: MockHash([0; 32]),
    hash: MockHash([1; 32]),
    txs_commitment: MockHash([1; 32]),
    height: 0,
    // 2023-01-01T00:00:00Z
    time: Time::from_secs(1672531200),
};

/// Definition of a fork that will be executed in `MockDaService` at specified height
pub struct PlannedFork {
    trigger_at_height: u64,
    fork_height: u64,
    blobs: Vec<Vec<u8>>,
}

impl PlannedFork {
    /// Creates new [`PlannedFork`]. Panics if some parameters are invalid.
    ///
    /// # Arguments
    ///
    /// * `trigger_at_height` - Height at which fork is "noticed".
    /// * `fork_height` - Height at which chain forked. Height of the first block in `blobs` will be `fork_height + 1`
    /// * `blobs` - Blobs that will be added after fork. Single blob per each block
    pub fn new(trigger_at_height: u64, fork_height: u64, blobs: Vec<Vec<u8>>) -> Self {
        if fork_height > trigger_at_height {
            panic!("Fork height must be less than trigger height");
        }
        let fork_len = (trigger_at_height - fork_height) as usize;
        if fork_len < blobs.len() {
            panic!("Not enough blobs for fork to be produced at given height");
        }
        Self {
            trigger_at_height,
            fork_height,
            blobs,
        }
    }
}

#[pin_project]
/// Stream of finalized headers
pub struct MockDaBlockHeaderStream {
    #[pin]
    inner: tokio_stream::wrappers::BroadcastStream<MockBlockHeader>,
}

impl MockDaBlockHeaderStream {
    /// Create new stream of finalized headers
    pub fn new(receiver: broadcast::Receiver<MockBlockHeader>) -> Self {
        Self {
            inner: tokio_stream::wrappers::BroadcastStream::new(receiver),
        }
    }
}

impl futures::Stream for MockDaBlockHeaderStream {
    type Item = Result<MockBlockHeader, anyhow::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project(); // Requires the pin-project crate or similar functionality
        this.inner
            .poll_next(cx)
            .map(|opt| opt.map(|res| res.map_err(Into::into)))
    }
}

/// DaService used in tests.
/// Currently only supports single blob per block.
/// Height of the first submitted block is 1.
/// Submitted blocks are kept indefinitely in memory.
#[derive(Clone)]
pub struct MockDaService {
    sequencer_da_address: MockAddress,
    // don't need a mutex, but DaService trait requires it by Sync trait
    pub(crate) blocks: Arc<AsyncMutex<DbConnector>>,
    /// How many blocks should be submitted, before block is finalized. 0 means instant finality.
    blocks_to_finality: u32,
    /// Used for calculating correct finality from state of `blocks`
    finalized_header_sender: broadcast::Sender<MockBlockHeader>,
    /// Used for sending transactions
    transaction_queue_sender:
        UnboundedSender<Option<SenderWithNotifier<<Self as DaService>::TransactionId>>>,
    wait_attempts: usize,
    planned_fork: Arc<Mutex<Option<PlannedFork>>>,
    worker_handle: CancellationToken,
}

impl MockDaService {
    /// Creates a new [`MockDaService`] with instant finality.
    pub fn new(sequencer_da_address: MockAddress, db_path: &Path) -> Self {
        Self::with_finality(sequencer_da_address, 0, db_path)
    }

    /// Create a new [`MockDaService`] with given finality.
    #[tracing::instrument(name = "MockDA")]
    pub fn with_finality(
        sequencer_da_address: MockAddress,
        blocks_to_finality: u32,
        db_path: &Path,
    ) -> Self {
        let (transaction_queue_sender, transaction_queue_receiver) =
            unbounded_channel::<Option<SenderWithNotifier<<Self as DaService>::TransactionId>>>();
        let (finalized_header_sender, finalized_header_receiver) = broadcast::channel(16);

        let da_service = Self {
            sequencer_da_address,
            blocks: Arc::new(AsyncMutex::new(DbConnector::new(db_path))),
            blocks_to_finality,
            finalized_header_sender,
            transaction_queue_sender,
            wait_attempts: 100_0000,
            planned_fork: Arc::new(Mutex::new(None)),
            worker_handle: CancellationToken::new(),
        };

        // Spawn the DA service worker task with a cancellation token
        // so that when the DA service instance is dropped, the tasks are cancelled.
        let cancellation_token = da_service.worker_handle.clone();
        let this = da_service.clone();
        tokio::spawn(this.da_service_worker(
            transaction_queue_receiver,
            finalized_header_receiver,
            cancellation_token,
        ));

        da_service
    }

    async fn da_service_worker(
        self,
        mut transaction_queue_receiver: UnboundedReceiver<
            Option<SenderWithNotifier<<Self as DaService>::TransactionId>>,
        >,
        mut finalized_header_receiver: Receiver<MockBlockHeader>,
        cancellation_token: CancellationToken,
    ) {
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                }
                req = transaction_queue_receiver.recv() => {
                    if let Some(Some(req)) = req {
                        let res = self.send_transaction(req.da_data).await;
                        let _ = req.notify.send(res);
                    }
                },
                header = finalized_header_receiver.recv() => {
                    if let Ok(header) = header {
                        tracing::debug!("Finalized MockHeader: {}", header);
                    }
                },
            }
        }
    }

    /// Get sequencer address
    pub fn get_sequencer_address(&self) -> MockAddress {
        self.sequencer_da_address
    }

    /// Change number of wait attempts before giving up on waiting for block
    pub fn set_wait_attempts(&mut self, wait_attempts: usize) {
        self.wait_attempts = wait_attempts;
    }

    async fn wait_for_height(&self, height: u64) -> anyhow::Result<()> {
        // Waits self.wait_attempts * 10ms to get block at height
        for _ in 0..self.wait_attempts {
            {
                if self.blocks.lock().await.get(height - 1).is_some() {
                    return Ok(());
                }
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        anyhow::bail!(
            "No block at height={height} has been sent in {:?}",
            Duration::from_millis((self.wait_attempts * 10) as u64),
        );
    }

    /// Rewrites existing non finalized blocks with given blocks
    /// New blobs will be added **after** specified height,
    /// meaning that first blob will be in the block of height + 1.
    pub async fn fork_at(&self, height: u64, blobs: Vec<Vec<u8>>) -> anyhow::Result<()> {
        let last_finalized_height = self.get_last_finalized_height().await;
        if last_finalized_height > height {
            anyhow::bail!(
                "Cannot fork at height {}, last finalized height is {}",
                height,
                last_finalized_height
            );
        }
        let blocks = self.blocks.lock().await;
        blocks.prune_above(height);

        for blob in blobs {
            use sov_rollup_interface::zk::Proof;
            let da_data = DaData::ZKProof(Proof::Full(blob));
            let blob = borsh::to_vec(&da_data).unwrap();
            self.add_blob(&blocks, blob, Default::default()).unwrap();
        }

        Ok(())
    }

    /// Set planned fork, that will be executed at specified height
    pub async fn set_planned_fork(&self, planned_fork: PlannedFork) -> anyhow::Result<()> {
        let last_finalized_height = self.get_last_finalized_height().await;
        if last_finalized_height > planned_fork.trigger_at_height {
            anyhow::bail!(
                "Cannot fork at height {}, last finalized height is {}",
                planned_fork.trigger_at_height,
                last_finalized_height
            );
        }

        let mut fork = self.planned_fork.lock().unwrap();
        *fork = Some(planned_fork);

        Ok(())
    }

    /// Returns the latest block number
    pub async fn get_height(&self) -> u64 {
        self.blocks.lock().await.len() as u64
    }

    async fn get_last_finalized_height(&self) -> u64 {
        self.blocks
            .lock()
            .await
            .len()
            .checked_sub(self.blocks_to_finality as usize)
            .unwrap_or_default() as u64
    }

    /// Adds a mock blob to the mock da layer for tests
    pub async fn publish_test_block(&self) -> anyhow::Result<()> {
        let blocks = self.blocks.lock().await;
        let blob = vec![];
        let _ = self.add_blob(&blocks, blob, Default::default())?;
        Ok(())
    }

    fn add_blob(
        &self,
        blocks: &AsyncMutexGuard<'_, DbConnector>,
        blob: Vec<u8>,
        zkp_proof: Vec<u8>,
    ) -> anyhow::Result<u64> {
        let (previous_block_hash, height) = match blocks.last().map(|b| b.header().clone()) {
            None => (GENESIS_HEADER.hash(), GENESIS_HEADER.height() + 1),
            Some(block_header) => (block_header.hash(), block_header.height + 1),
        };

        let data_hash = hash_to_array(&blob);
        let proof_hash = hash_to_array(&zkp_proof);
        // Hash only from single blob
        let block_hash = block_hash(height, data_hash, proof_hash, previous_block_hash.into());

        let blob = MockBlob::new_with_zkp_proof(
            blob.to_vec(),
            zkp_proof,
            self.sequencer_da_address,
            data_hash,
        );
        let header = MockBlockHeader {
            prev_hash: previous_block_hash,
            hash: block_hash,
            txs_commitment: block_hash,
            height,
            time: Time::from_secs(10000000000), // TODO: had to mock this for now, causes different state roots
        };
        let block = MockBlock {
            header,
            validity_cond: Default::default(),
            blobs: vec![blob],
        };

        blocks.push_back(block.clone());

        // Enough blocks to finalize block
        if blocks.len() > self.blocks_to_finality as usize {
            let next_index_to_finalize = blocks.len() - self.blocks_to_finality as usize - 1;
            let next_finalized_header = blocks
                .get(next_index_to_finalize as u64)
                .unwrap()
                .header()
                .clone();
            self.finalized_header_sender
                .send(next_finalized_header)
                .unwrap();
        }

        Ok(height)
    }

    /// Executes planned fork if it is planned at given height
    async fn planned_fork_handler(&self, height: u64) -> anyhow::Result<()> {
        let planned_fork_now = {
            let mut planned_fork_guard = self.planned_fork.lock().unwrap();
            if planned_fork_guard
                .as_ref()
                .map_or(false, |x| x.trigger_at_height == height)
            {
                Some(planned_fork_guard.take().unwrap())
            } else {
                None
            }
        };
        if let Some(planned_fork_now) = planned_fork_now {
            self.fork_at(planned_fork_now.fork_height, planned_fork_now.blobs)
                .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl DaService for MockDaService {
    type Spec = MockDaSpec;
    type Verifier = MockDaVerifier;
    type FilteredBlock = MockBlock;
    type HeaderStream = MockDaBlockHeaderStream;
    type TransactionId = MockHash;
    type Error = anyhow::Error;
    type BlockHash = [u8; 32];

    /// Gets block at given height
    /// If block is not available, waits until it is
    /// It is possible to read non-finalized and last finalized blocks multiple times
    /// Finalized blocks must be read in order.
    async fn get_block_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        if height == 0 {
            anyhow::bail!("The lowest queryable block should be > 0");
        }
        // Fork logic
        self.planned_fork_handler(height).await?;

        // This is some mid level fix.
        // In tests and demos only height 0 exists
        // we don't want to wait 5 seconds until block 1 is created
        // so if get block at 1 is called, we create it
        let blocks = self.blocks.lock().await;

        let len = blocks.len() as u64;
        if len == 0 && height == 1 {
            let _ = self.add_blob(&blocks, Default::default(), Default::default())?;
        }

        // if wait for height doesn't lock its own blocks, can't make it async
        // DbConnector is not Send
        std::mem::drop(blocks);
        // Block until there's something
        self.wait_for_height(height).await?;
        // Locking blocks here, so submissions has to wait
        let blocks = self.blocks.lock().await;
        let oldest_available_height = blocks.get(0).unwrap().header.height;
        let index = height
            .checked_sub(oldest_available_height)
            .ok_or(anyhow::anyhow!(
                "Block at height {} is not available anymore",
                height
            ))?;

        Ok(blocks.get(index).unwrap().clone())
    }

    async fn get_last_finalized_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error> {
        let blocks_len = self.blocks.lock().await.len();

        if blocks_len < self.blocks_to_finality as usize + 1 {
            return Ok(GENESIS_HEADER);
        }

        let blocks = self.blocks.lock().await;
        let index = blocks_len - self.blocks_to_finality as usize - 1;
        Ok(blocks.get(index as u64).unwrap().header().clone())
    }

    async fn subscribe_finalized_header(&self) -> Result<Self::HeaderStream, Self::Error> {
        let receiver = self.finalized_header_sender.subscribe();
        Ok(MockDaBlockHeaderStream::new(receiver))
    }

    async fn get_head_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error> {
        let blocks = self.blocks.lock().await;

        Ok(blocks
            .last()
            .map(|b| b.header().clone())
            .unwrap_or(GENESIS_HEADER))
    }

    fn extract_relevant_blobs(
        &self,
        block: &Self::FilteredBlock,
    ) -> Vec<<Self::Spec as DaSpec>::BlobTransaction> {
        let mut res = vec![];
        for b in block.blobs.clone() {
            let mut clone_for_full_data = b.clone();
            let full_data = clone_for_full_data.full_data();
            if DaDataBatchProof::try_from_slice(full_data).is_ok() {
                res.push(b)
            }
        }
        res
    }

    async fn extract_relevant_proofs(
        &self,
        block: &Self::FilteredBlock,
        _prover_pk: &[u8],
    ) -> anyhow::Result<Vec<Proof>> {
        let mut res = vec![];
        for mut b in block.blobs.clone() {
            if let Ok(r) = DaDataLightClient::try_from_slice(b.full_data()) {
                match r {
                    DaDataLightClient::Complete(proof) => {
                        res.push(proof);
                    }
                    _ => {
                        panic!("Unexpected type");
                    }
                }
            }
        }
        Ok(res)
    }

    async fn get_extraction_proof(
        &self,
        _block: &Self::FilteredBlock,
        _blobs: &[<Self::Spec as DaSpec>::BlobTransaction],
    ) -> (
        <Self::Spec as DaSpec>::InclusionMultiProof,
        <Self::Spec as DaSpec>::CompletenessProof,
    ) {
        ([0u8; 32], ())
    }

    #[tracing::instrument(name = "MockDA", level = "debug", skip_all)]
    async fn send_transaction(&self, da_data: DaData) -> Result<Self::TransactionId, Self::Error> {
        let blob = match da_data {
            DaData::ZKProof(proof) => {
                tracing::debug!("Adding a zkproof");
                let data = DaDataLightClient::Complete(proof);
                borsh::to_vec(&data).unwrap()
            }
            DaData::SequencerCommitment(seq_comm) => {
                tracing::debug!("Adding a sequencer commitment");
                let data = DaData::SequencerCommitment(seq_comm);
                borsh::to_vec(&data).unwrap()
            }
        };
        let blocks = self.blocks.lock().await;
        let _ = self.add_blob(&blocks, blob, Default::default())?;
        Ok(MockHash([0; 32]))
    }

    fn get_send_transaction_queue(
        &self,
    ) -> UnboundedSender<Option<SenderWithNotifier<Self::TransactionId>>> {
        self.transaction_queue_sender.clone()
    }

    async fn send_aggregated_zk_proof(&self, proof: &[u8]) -> Result<u64, Self::Error> {
        let blocks = self.blocks.lock().await;

        self.add_blob(&blocks, Default::default(), proof.to_vec())
    }

    async fn get_aggregated_proofs_at(&self, height: u64) -> Result<Vec<Vec<u8>>, Self::Error> {
        let blobs = self.get_block_at(height).await?.blobs;
        Ok(blobs.into_iter().map(|b| b.zk_proofs_data).collect())
    }

    async fn get_fee_rate(&self) -> Result<u128, Self::Error> {
        // Mock constant, use min possible in bitcoin
        Ok(2500000000_u128)
    }

    async fn get_block_by_hash(
        &self,
        hash: Self::BlockHash,
    ) -> Result<Self::FilteredBlock, Self::Error> {
        self.blocks
            .lock()
            .await
            .get_by_hash(hash)
            .ok_or_else(|| anyhow::anyhow!("Block with hash {:?} not found", hash))
    }

    async fn get_relevant_blobs_of_pending_transactions(
        &self,
    ) -> Vec<<Self::Spec as DaSpec>::BlobTransaction> {
        vec![]
    }
}

impl Drop for MockDaService {
    fn drop(&mut self) {
        self.worker_handle.cancel();
    }
}

fn hash_to_array(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result
        .as_slice()
        .try_into()
        .expect("SHA256 should be 32 bytes")
}

fn block_hash(
    height: u64,
    data_hash: [u8; 32],
    proof_hash: [u8; 32],
    prev_hash: [u8; 32],
) -> MockHash {
    let mut block_to_hash = height.to_be_bytes().to_vec();
    block_to_hash.extend_from_slice(&data_hash[..]);
    block_to_hash.extend_from_slice(&proof_hash[..]);
    block_to_hash.extend_from_slice(&prev_hash[..]);

    MockHash::from(hash_to_array(&block_to_hash))
}

#[cfg(test)]
mod tests {
    use sov_rollup_interface::da::{BlobReaderTrait, BlockHeaderTrait};
    use sov_rollup_interface::zk::Proof;
    use tokio::task::JoinHandle;
    use tokio_stream::StreamExt;

    use super::*;

    #[tokio::test]
    async fn test_empty() {
        let db_path = tempfile::tempdir().unwrap();
        let mut da = MockDaService::new(MockAddress::new([1; 32]), db_path.path());
        da.wait_attempts = 10;

        let last_finalized_header = da.get_last_finalized_block_header().await.unwrap();
        assert_eq!(GENESIS_HEADER, last_finalized_header);

        let head_header = da.get_head_block_header().await.unwrap();
        assert_eq!(GENESIS_HEADER, head_header);

        let zero_block = da.get_block_at(0).await;
        assert!(zero_block.is_err());
        assert_eq!(
            "The lowest queryable block should be > 0",
            zero_block.unwrap_err().to_string()
        );

        {
            let has_planned_fork = da.planned_fork.lock().unwrap();
            assert!(has_planned_fork.is_none());
        }
    }

    async fn get_finalized_headers_collector(
        da: &mut MockDaService,
        expected_num_headers: usize,
    ) -> JoinHandle<Vec<MockBlockHeader>> {
        let mut receiver: MockDaBlockHeaderStream = da.subscribe_finalized_header().await.unwrap();
        // All finalized headers should be pushed by that time
        // This prevents test for freezing in case of a bug
        // But we need to wait longer, as `MockDa
        let timeout_duration = Duration::from_millis(1000);

        // This task runs for as long as we are still expecting blocks and will stop eventually.
        // Therefore, this is not considered to be an escaping task.
        tokio::spawn(async move {
            let mut received = Vec::with_capacity(expected_num_headers);
            for _ in 0..expected_num_headers {
                match time::timeout(timeout_duration, receiver.next()).await {
                    Ok(Some(Ok(header))) => received.push(header),
                    _ => break,
                }
            }
            received
        })
    }

    // Checks that last finalized height is always less than last submitted by blocks_to_finalization
    fn validate_get_finalized_header_response(
        submit_height: u64,
        blocks_to_finalization: u64,
        response: anyhow::Result<MockBlockHeader>,
    ) {
        let finalized_header = response.unwrap();
        if let Some(expected_finalized_height) = submit_height.checked_sub(blocks_to_finalization) {
            assert_eq!(expected_finalized_height, finalized_header.height());
        } else {
            assert_eq!(GENESIS_HEADER, finalized_header);
        }
    }

    async fn test_push_and_read(finalization: u64, num_blocks: usize) {
        let db_path = tempfile::tempdir().unwrap();
        let mut da = MockDaService::with_finality(
            MockAddress::new([1; 32]),
            finalization as u32,
            db_path.path(),
        );
        da.blocks.lock().await.delete_all_rows();
        da.wait_attempts = 2;
        let number_of_finalized_blocks = num_blocks - finalization as usize;
        let collector_handle =
            get_finalized_headers_collector(&mut da, number_of_finalized_blocks).await;

        for i in 0..num_blocks {
            let proof = Proof::Full(vec![i as u8; i + 1]);
            let published_blob = DaData::ZKProof(proof.clone());
            let height = (i + 1) as u64;

            da.send_transaction(published_blob.clone()).await.unwrap();

            let mut block = da.get_block_at(height).await.unwrap();

            assert_eq!(height, block.header.height());
            assert_eq!(1, block.blobs.len());
            let blob = &mut block.blobs[0];
            let retrieved_data = blob.full_data().to_vec();
            let retrieved_data = DaDataLightClient::try_from_slice(&retrieved_data).unwrap();
            let DaDataLightClient::Complete(retrieved_proof) = retrieved_data else {
                panic!("unexpected type");
            };
            assert_eq!(proof, retrieved_proof);

            let last_finalized_block_response = da.get_last_finalized_block_header().await;
            validate_get_finalized_header_response(
                height,
                finalization,
                last_finalized_block_response,
            );
        }

        let received = collector_handle.await.unwrap();
        let heights: Vec<u64> = received.iter().map(|h| h.height()).collect();
        let expected_heights: Vec<u64> = (1..=number_of_finalized_blocks as u64).collect();
        assert_eq!(expected_heights, heights);
    }

    async fn test_push_many_then_read(finalization: u64, num_blocks: usize) {
        let db_path = tempfile::tempdir().unwrap();
        let mut da = MockDaService::with_finality(
            MockAddress::new([1; 32]),
            finalization as u32,
            db_path.path(),
        );
        da.blocks.lock().await.delete_all_rows();

        da.wait_attempts = 2;
        let number_of_finalized_blocks = num_blocks - finalization as usize;
        let collector_handle =
            get_finalized_headers_collector(&mut da, number_of_finalized_blocks).await;

        let blobs: Vec<Vec<u8>> = (0..num_blocks).map(|i| vec![i as u8; i + 1]).collect();

        // Submitting blobs first
        for (i, blob) in blobs.iter().enumerate() {
            let height = (i + 1) as u64;
            // Send transaction should pass
            da.send_transaction(DaData::ZKProof(Proof::Full(blob.to_owned())))
                .await
                .unwrap();
            let last_finalized_block_response = da.get_last_finalized_block_header().await;
            validate_get_finalized_header_response(
                height,
                finalization,
                last_finalized_block_response,
            );

            let head_block_header = da.get_head_block_header().await.unwrap();
            assert_eq!(height, head_block_header.height());
        }

        // Starts from 0
        let expected_head_height = num_blocks as u64;
        let expected_finalized_height = expected_head_height - finalization;

        // Then read
        for (i, blob) in blobs.into_iter().enumerate() {
            let i = (i + 1) as u64;

            let mut fetched_block = da.get_block_at(i).await.unwrap();
            assert_eq!(i, fetched_block.header().height());

            let last_finalized_header = da.get_last_finalized_block_header().await.unwrap();
            assert_eq!(expected_finalized_height, last_finalized_header.height());

            let proof = Proof::Full(blob);
            let retrieved_data = fetched_block.blobs[0].full_data();
            let retrieved_data = DaDataLightClient::try_from_slice(retrieved_data).unwrap();
            let DaDataLightClient::Complete(retrieved_proof) = retrieved_data else {
                panic!("unexpected type");
            };
            assert_eq!(proof, retrieved_proof);

            let head_block_header = da.get_head_block_header().await.unwrap();
            assert_eq!(expected_head_height, head_block_header.height());
        }

        let received = collector_handle.await.unwrap();
        let finalized_heights: Vec<u64> = received.iter().map(|h| h.height()).collect();
        let expected_finalized_heights: Vec<u64> =
            (1..=number_of_finalized_blocks as u64).collect();
        assert_eq!(expected_finalized_heights, finalized_heights);
    }

    mod instant_finality {
        use super::*;
        #[tokio::test]
        /// Pushing a blob and immediately reading it
        async fn push_pull_single_thread() {
            test_push_and_read(0, 10).await;
        }

        #[tokio::test]
        async fn push_many_then_read() {
            test_push_many_then_read(0, 10).await;
        }
    }

    mod non_instant_finality {
        use super::*;

        #[tokio::test]
        async fn push_pull_single_thread() {
            test_push_and_read(1, 10).await;
            test_push_and_read(3, 10).await;
            test_push_and_read(5, 10).await;
        }

        #[tokio::test]
        async fn push_many_then_read() {
            test_push_many_then_read(1, 10).await;
            test_push_many_then_read(3, 10).await;
            test_push_many_then_read(5, 10).await;
        }

        #[tokio::test]
        async fn read_multiple_times() {
            let db_path = tempfile::tempdir().unwrap();
            let mut da = MockDaService::with_finality(MockAddress::new([1; 32]), 4, db_path.path());
            da.wait_attempts = 2;

            // 1 -> 2 -> 3

            da.send_transaction(DaData::ZKProof(Proof::Full(vec![1, 2, 3, 4])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![4, 5, 6, 7])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![8, 9, 0, 1])))
                .await
                .unwrap();

            let block_1_before = da.get_block_at(1).await.unwrap();
            let block_2_before = da.get_block_at(2).await.unwrap();
            let block_3_before = da.get_block_at(3).await.unwrap();

            // Disabling this check because our modified mock da creates blocks whena a transaction is sent
            // let result = da.get_block_at(4).await;
            // assert!(result.is_err());

            let block_1_after = da.get_block_at(1).await.unwrap();
            let block_2_after = da.get_block_at(2).await.unwrap();
            let block_3_after = da.get_block_at(3).await.unwrap();

            assert_eq!(block_1_before, block_1_after);
            assert_eq!(block_2_before, block_2_after);
            assert_eq!(block_3_before, block_3_after);
            // Just some sanity check
            assert_ne!(block_1_before, block_2_before);
            assert_ne!(block_3_before, block_1_before);
            assert_ne!(block_1_before, block_2_after);
        }
    }

    #[tokio::test]
    async fn test_zk_submission() -> Result<(), anyhow::Error> {
        let db_path = tempfile::tempdir().unwrap();
        let da = MockDaService::new(MockAddress::new([1; 32]), db_path.path());
        let aggregated_proof_data = vec![1, 2, 3];
        let height = da.send_aggregated_zk_proof(&aggregated_proof_data).await?;
        let proofs = da.get_aggregated_proofs_at(height).await?;

        assert_eq!(vec![aggregated_proof_data], proofs);
        Ok(())
    }

    mod reo4g_control {
        use super::*;
        use crate::{MockAddress, MockDaService};

        #[tokio::test]
        async fn test_reorg_control_success() {
            let db_path = tempfile::tempdir().unwrap();
            let da = MockDaService::with_finality(MockAddress::new([1; 32]), 4, db_path.path());

            // 1 -> 2 -> 3.1 -> 4.1
            //      \ -> 3.2 -> 4.2

            // 1
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![1, 2, 3, 4])))
                .await
                .unwrap();
            // 2
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![4, 5, 6, 7])))
                .await
                .unwrap();
            // 3.1
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![8, 9, 0, 1])))
                .await
                .unwrap();
            // 4.1
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![2, 3, 4, 5])))
                .await
                .unwrap();

            let _block_1 = da.get_block_at(1).await.unwrap();
            let block_2 = da.get_block_at(2).await.unwrap();
            let block_3 = da.get_block_at(3).await.unwrap();
            let head_before = da.get_head_block_header().await.unwrap();

            // Do reorg
            da.fork_at(2, vec![vec![3, 3, 3, 3], vec![4, 4, 4, 4]])
                .await
                .unwrap();

            let block_3_after = da.get_block_at(3).await.unwrap();
            assert_ne!(block_3, block_3_after);

            assert_eq!(block_2.header().hash(), block_3_after.header().prev_hash());

            let head_after = da.get_head_block_header().await.unwrap();
            assert_ne!(head_before, head_after);
        }

        #[tokio::test]
        async fn test_attempt_reorg_after_finalized() {
            let db_path = tempfile::tempdir().unwrap();
            let da = MockDaService::with_finality(MockAddress::new([1; 32]), 2, db_path.path());

            // 1 -> 2 -> 3 -> 4

            da.send_transaction(DaData::ZKProof(Proof::Full(vec![1, 2, 3, 4])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![4, 5, 6, 7])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![8, 9, 0, 1])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![2, 3, 4, 5])))
                .await
                .unwrap();

            let block_1_before = da.get_block_at(1).await.unwrap();
            let block_2_before = da.get_block_at(2).await.unwrap();
            let block_3_before = da.get_block_at(3).await.unwrap();
            let block_4_before = da.get_block_at(4).await.unwrap();
            let finalized_header_before = da.get_last_finalized_block_header().await.unwrap();
            assert_eq!(&finalized_header_before, block_2_before.header());

            // Attempt at finalized header. It will try to overwrite height 2 and 3
            let result = da
                .fork_at(1, vec![vec![3, 3, 3, 3], vec![4, 4, 4, 4]])
                .await;
            assert!(result.is_err());
            assert_eq!(
                "Cannot fork at height 1, last finalized height is 2",
                result.unwrap_err().to_string()
            );

            let block_1_after = da.get_block_at(1).await.unwrap();
            let block_2_after = da.get_block_at(2).await.unwrap();
            let block_3_after = da.get_block_at(3).await.unwrap();
            let block_4_after = da.get_block_at(4).await.unwrap();
            let finalized_header_after = da.get_last_finalized_block_header().await.unwrap();
            assert_eq!(&finalized_header_after, block_2_after.header());

            assert_eq!(block_1_before, block_1_after);
            assert_eq!(block_2_before, block_2_after);
            assert_eq!(block_3_before, block_3_after);
            assert_eq!(block_4_before, block_4_after);

            // Overwriting height 3 and 4 is ok
            let result2 = da
                .fork_at(2, vec![vec![3, 3, 3, 3], vec![4, 4, 4, 4]])
                .await;
            assert!(result2.is_ok());
            let block_2_after_reorg = da.get_block_at(2).await.unwrap();
            let block_3_after_reorg = da.get_block_at(3).await.unwrap();

            assert_eq!(block_2_after, block_2_after_reorg);
            assert_ne!(block_3_after, block_3_after_reorg);
        }

        #[tokio::test]
        async fn test_planned_reorg() {
            let db_path = tempfile::tempdir().unwrap();
            let mut da = MockDaService::with_finality(MockAddress::new([1; 32]), 4, db_path.path());
            da.wait_attempts = 2;

            // Planned for will replace blocks at height 3 and 4
            let planned_fork = PlannedFork::new(4, 2, vec![vec![3, 3, 3, 3], vec![4, 4, 4, 4]]);

            da.set_planned_fork(planned_fork).await.unwrap();
            {
                let has_planned_fork = da.planned_fork.lock().unwrap();
                assert!(has_planned_fork.is_some());
            }

            da.send_transaction(DaData::ZKProof(Proof::Full(vec![1, 2, 3, 4])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![4, 5, 6, 7])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![8, 9, 0, 1])))
                .await
                .unwrap();

            let block_1_before = da.get_block_at(1).await.unwrap();
            let block_2_before = da.get_block_at(2).await.unwrap();
            assert_consecutive_blocks(&block_1_before, &block_2_before);
            let block_3_before = da.get_block_at(3).await.unwrap();
            assert_consecutive_blocks(&block_2_before, &block_3_before);
            let block_4 = da.get_block_at(4).await.unwrap();
            {
                let has_planned_fork = da.planned_fork.lock().unwrap();
                assert!(!has_planned_fork.is_some());
            }

            // Fork is happening!
            assert_ne!(block_3_before.header().hash(), block_4.header().prev_hash());
            let block_3_after = da.get_block_at(3).await.unwrap();
            assert_consecutive_blocks(&block_3_after, &block_4);
            assert_consecutive_blocks(&block_2_before, &block_3_after);
        }

        #[tokio::test]
        async fn test_planned_reorg_shorter() {
            let db_path = tempfile::tempdir().unwrap();
            let mut da = MockDaService::with_finality(MockAddress::new([1; 32]), 4, db_path.path());
            da.wait_attempts = 2;
            // Planned for will replace blocks at height 3 and 4
            let planned_fork =
                PlannedFork::new(4, 2, vec![vec![13, 13, 13, 13], vec![14, 14, 14, 14]]);
            da.set_planned_fork(planned_fork).await.unwrap();

            da.send_transaction(DaData::ZKProof(Proof::Full(vec![1, 1, 1, 1])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![2, 2, 2, 2])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![3, 3, 3, 3])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![4, 4, 4, 4])))
                .await
                .unwrap();
            da.send_transaction(DaData::ZKProof(Proof::Full(vec![5, 5, 5, 5])))
                .await
                .unwrap();

            let block_1_before = da.get_block_at(1).await.unwrap();
            let block_2_before = da.get_block_at(2).await.unwrap();
            assert_consecutive_blocks(&block_1_before, &block_2_before);
            let block_3_before = da.get_block_at(3).await.unwrap();
            assert_consecutive_blocks(&block_2_before, &block_3_before);
            let block_4 = da.get_block_at(4).await.unwrap();
            assert_ne!(block_4.header().prev_hash(), block_3_before.header().hash());
            let block_1_after = da.get_block_at(1).await.unwrap();
            let block_2_after = da.get_block_at(2).await.unwrap();
            let block_3_after = da.get_block_at(3).await.unwrap();
            assert_consecutive_blocks(&block_3_after, &block_4);
            assert_consecutive_blocks(&block_2_after, &block_3_after);
            assert_consecutive_blocks(&block_1_after, &block_2_after);

            // Disabling this check because our modification to MockDaService
            // will create the blocks that were asked, as if they are always available
            // let block_5 = da.get_block_at(5).await;
            // assert_eq!(
            //     "No block at height=5 has been sent in 20ms",
            //     block_5.unwrap_err().to_string()
            // );
        }
    }

    fn assert_consecutive_blocks(block1: &MockBlock, block2: &MockBlock) {
        assert_eq!(block2.header().prev_hash(), block1.header().hash())
    }
}
