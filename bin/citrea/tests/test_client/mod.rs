use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use alloy::providers::network::{Ethereum, EthereumWallet};
use alloy::providers::{PendingTransactionBuilder, Provider as AlloyProvider, ProviderBuilder};
use alloy::rpc::types::eth::{Block, Transaction, TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::{Http, HyperClient};
use citrea_batch_prover::GroupCommitments;
use citrea_evm::{Filter, LogResponse};
use ethereum_rpc::SyncStatus;
use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{PingConfig, WsClient, WsClientBuilder};
use reth_primitives::{Address, BlockId, BlockNumberOrTag, Bytes, TxHash, TxKind, B256, U256, U64};
use reth_rpc_types::trace::geth::{GethDebugTracingOptions, GethTrace};
use reth_rpc_types::RichBlock;
use sequencer_client::GetSoftConfirmationResponse;
use sov_ledger_rpc::client::RpcClient;
use sov_ledger_rpc::HexHash;
use sov_rollup_interface::rpc::{
    BatchProofResponse, LastVerifiedBatchProofResponse, SequencerCommitmentResponse,
    SoftConfirmationResponse, SoftConfirmationStatus, VerifiedBatchProofResponse,
};

pub const SEND_ETH_GAS: u128 = 21001;
pub const MAX_FEE_PER_GAS: u128 = 1000000001;

pub struct TestClient {
    pub(crate) chain_id: u64,
    pub(crate) from_addr: Address,
    //client: SignerMiddleware<Provider<Http>, PrivateKeySigner>,
    client: Box<dyn AlloyProvider<Http<HyperClient>>>,
    http_client: HttpClient,
    ws_client: WsClient,
    current_nonce: AtomicU64,
    pub(crate) rpc_addr: std::net::SocketAddr,
}

impl TestClient {
    pub(crate) async fn new(
        chain_id: u64,
        key: PrivateKeySigner,
        from_addr: Address,
        rpc_addr: std::net::SocketAddr,
    ) -> anyhow::Result<Self> {
        let http_host = format!("http://localhost:{}", rpc_addr.port());
        let ws_host = format!("ws://localhost:{}", rpc_addr.port());

        let provider = ProviderBuilder::new()
            // .with_recommended_fillers()
            .with_chain_id(chain_id)
            .wallet(EthereumWallet::from(key))
            .on_hyper_http(http_host.parse().unwrap());
        let client: Box<dyn AlloyProvider<Http<HyperClient>>> = Box::new(provider);

        let http_client = HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(120))
            .build(http_host)?;

        let ws_client = WsClientBuilder::default()
            .enable_ws_ping(PingConfig::default().inactive_limit(Duration::from_secs(10)))
            .build(ws_host)
            .await?;

        let client = Self {
            chain_id,
            from_addr,
            client,
            ws_client,
            http_client,
            current_nonce: AtomicU64::new(0),
            rpc_addr,
        };
        client.sync_nonce().await;
        Ok(client)
    }

    pub(crate) async fn healthcheck(&self) -> Result<u16, Box<dyn std::error::Error>> {
        let healthcheck_url = format!("http://localhost:{}/health", self.rpc_addr.port());
        let resp = reqwest::get(healthcheck_url).await?;
        Ok(resp.status().as_u16())
    }

    pub(crate) async fn spam_publish_batch_request(
        &self,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.http_client
            .request("citrea_testPublishBlock", rpc_params![])
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn send_publish_batch_request(&self) {
        let _: () = self
            .http_client
            .request("citrea_testPublishBlock", rpc_params![])
            .await
            .unwrap();
        // Do not decrease the sleep time, otherwise the test will fail!
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    pub(crate) async fn sync_nonce(&self) {
        let nonce = self
            .eth_get_transaction_count(self.from_addr, None)
            .await
            .unwrap();
        self.current_nonce.store(nonce, Ordering::Relaxed);
    }

    pub(crate) async fn deploy_contract(
        &self,
        byte_code: Vec<u8>,
        nonce: Option<u64>,
    ) -> Result<
        PendingTransactionBuilder<'_, Http<HyperClient>, Ethereum>,
        Box<dyn std::error::Error>,
    > {
        let nonce = match nonce {
            Some(nonce) => nonce,
            None => self.current_nonce.fetch_add(1, Ordering::Relaxed),
        };

        let mut req = TransactionRequest::default()
            .from(self.from_addr)
            .input(byte_code.into());
        req.to = Some(TxKind::Create);
        let gas = self.client.estimate_gas(&req).await.unwrap();

        let req = req
            .gas_limit(gas)
            .nonce(nonce)
            .max_priority_fee_per_gas(10)
            .max_fee_per_gas(MAX_FEE_PER_GAS);

        let receipt_req = self.client.send_transaction(req).await?;
        Ok(receipt_req)
    }

    pub(crate) async fn deploy_contract_call(
        &self,
        byte_code: Vec<u8>,
        nonce: Option<u64>,
    ) -> Result<Bytes, Box<dyn std::error::Error>> {
        let nonce = match nonce {
            Some(nonce) => nonce,
            None => self.current_nonce.load(Ordering::Relaxed),
        };

        let req = TransactionRequest::default()
            .from(self.from_addr)
            .input(byte_code.into())
            .nonce(nonce);
        let gas = self.client.estimate_gas(&req).await.unwrap();

        let req = req
            .gas_limit(gas)
            .max_priority_fee_per_gas(10)
            .max_fee_per_gas(MAX_FEE_PER_GAS);

        let receipt_req = self.client.call(&req).await?;

        Ok(receipt_req)
    }

    pub(crate) async fn contract_transaction(
        &self,
        contract_address: Address,
        data: Vec<u8>,
        nonce: Option<u64>,
    ) -> PendingTransactionBuilder<'_, Http<HyperClient>, Ethereum> {
        let nonce = match nonce {
            Some(nonce) => nonce,
            None => self.current_nonce.fetch_add(1, Ordering::Relaxed),
        };
        let req = TransactionRequest::default()
            .from(self.from_addr)
            .to(contract_address)
            .input(data.into());

        let gas = self.client.estimate_gas(&req).await.unwrap();

        let req = req
            .gas_limit(gas)
            .nonce(nonce)
            .max_priority_fee_per_gas(10)
            .max_fee_per_gas(MAX_FEE_PER_GAS);

        self.client.send_transaction(req).await.unwrap()
    }

    #[allow(dead_code)]
    pub(crate) async fn contract_transaction_with_custom_fee(
        &self,
        contract_address: Address,
        data: Vec<u8>,
        max_priority_fee_per_gas: u64,
        max_fee_per_gas: u64,
        value: Option<u64>,
        nonce: Option<u64>,
    ) -> PendingTransactionBuilder<'_, Http<HyperClient>, Ethereum> {
        let nonce = match nonce {
            Some(nonce) => nonce,
            None => self.current_nonce.fetch_add(1, Ordering::Relaxed),
        };
        let req = TransactionRequest::default()
            .from(self.from_addr)
            .to(contract_address)
            .input(data.into())
            .value(value.map(U256::from).unwrap_or_default());

        let gas = self.client.estimate_gas(&req).await.unwrap();

        let req = req
            .gas_limit(gas)
            .nonce(nonce)
            .max_priority_fee_per_gas(max_priority_fee_per_gas.into())
            .max_fee_per_gas(max_fee_per_gas.into());

        self.client.send_transaction(req).await.unwrap()
    }

    pub(crate) async fn contract_call<T: FromStr>(
        &self,
        contract_address: Address,
        data: Vec<u8>,
        _nonce: Option<u64>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let req = TransactionRequest::default()
            .from(self.from_addr)
            .to(contract_address)
            .input(data.into());

        let receipt_req = self.client.call(&req).await?;

        T::from_str(&receipt_req.to_string()).map_err(|_| "Failed to parse bytes".into())
    }

    pub(crate) async fn send_eth(
        &self,
        to_addr: Address,
        max_priority_fee_per_gas: Option<u128>,
        max_fee_per_gas: Option<u128>,
        nonce: Option<u64>,
        value: u128,
    ) -> Result<PendingTransactionBuilder<'_, Http<HyperClient>, Ethereum>, anyhow::Error> {
        let nonce = match nonce {
            Some(nonce) => nonce,
            None => self.current_nonce.fetch_add(1, Ordering::Relaxed),
        };

        let req = TransactionRequest::default()
            .from(self.from_addr)
            .to(to_addr)
            .value(U256::from(value))
            .gas_limit(SEND_ETH_GAS)
            .nonce(nonce)
            .max_priority_fee_per_gas(max_priority_fee_per_gas.unwrap_or(10))
            .max_fee_per_gas(max_fee_per_gas.unwrap_or(MAX_FEE_PER_GAS));

        self.client
            .send_transaction(req)
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn send_eth_with_gas(
        &self,
        to_addr: Address,
        max_priority_fee_per_gas: Option<u128>,
        max_fee_per_gas: Option<u128>,
        gas: u128,
        value: u128,
    ) -> Result<PendingTransactionBuilder<'_, Http<HyperClient>, Ethereum>, anyhow::Error> {
        let nonce = self.current_nonce.fetch_add(1, Ordering::Relaxed);

        let req = TransactionRequest::default()
            .from(self.from_addr)
            .to(to_addr)
            .value(U256::from(value))
            .gas_limit(gas)
            .nonce(nonce)
            .max_priority_fee_per_gas(max_priority_fee_per_gas.unwrap_or(10))
            .max_fee_per_gas(max_fee_per_gas.unwrap_or(MAX_FEE_PER_GAS));

        self.client
            .send_transaction(req)
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn web3_client_version(&self) -> String {
        self.http_client
            .request("web3_clientVersion", rpc_params![])
            .await
            .unwrap()
    }

    pub(crate) async fn web3_sha3(&self, bytes: String) -> String {
        self.http_client
            .request("web3_sha3", rpc_params![bytes])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_accounts(&self) -> Vec<Address> {
        self.http_client
            .request("eth_accounts", rpc_params![])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_chain_id(&self) -> u64 {
        self.client.get_chain_id().await.unwrap()
    }

    pub(crate) async fn eth_get_balance(
        &self,
        address: Address,
        block_id: Option<BlockId>,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        self.http_client
            .request("eth_getBalance", rpc_params![address, block_id])
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn eth_get_storage_at(
        &self,
        address: Address,
        index: U256,
        block_id: Option<BlockId>,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        self.http_client
            .request("eth_getStorageAt", rpc_params![address, index, block_id])
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn eth_get_code(
        &self,
        address: Address,
        block_id: Option<BlockId>,
    ) -> Result<Bytes, Box<dyn std::error::Error>> {
        self.http_client
            .request("eth_getCode", rpc_params![address, block_id])
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn eth_get_transaction_count(
        &self,
        address: Address,
        block_id: Option<BlockId>,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        match self
            .http_client
            .request::<U64, _>("eth_getTransactionCount", rpc_params![address, block_id])
            .await
        {
            Ok(count) => Ok(count.saturating_to()),
            Err(e) => Err(e.into()),
        }
    }

    // TODO actually this function returns gas price from the last block (already committed) and it may
    //  be different from the current gas price (for the next block being committed).
    //  So because of that users can't fully rely on the returned value.
    //  A part of https://github.com/chainwayxyz/citrea/issues/150
    pub(crate) async fn eth_gas_price(&self) -> U256 {
        self.http_client
            .request("eth_gasPrice", rpc_params![])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_fee_history(
        &self,
        block_count: String,
        newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
    ) -> FeeHistory {
        let rpc_params = rpc_params![block_count, newest_block, reward_percentiles];
        self.http_client
            .request("eth_feeHistory", rpc_params)
            .await
            .unwrap()
    }

    pub(crate) async fn eth_get_block_by_number(
        &self,
        block_number: Option<BlockNumberOrTag>,
    ) -> Block {
        self.http_client
            .request("eth_getBlockByNumber", rpc_params![block_number, false])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_get_block_by_number_with_detail(
        &self,
        block_number: Option<BlockNumberOrTag>,
    ) -> Block {
        self.http_client
            .request("eth_getBlockByNumber", rpc_params![block_number, true])
            .await
            .unwrap()
    }

    #[allow(dead_code)]
    pub(crate) async fn eth_get_transaction_by_hash(
        &self,
        tx_hash: TxHash,
        mempool_only: Option<bool>,
    ) -> Option<Transaction> {
        self.http_client
            .request(
                "eth_getTransactionByHash",
                rpc_params![tx_hash, mempool_only],
            )
            .await
            .unwrap()
    }

    pub(crate) async fn eth_get_block_receipts(
        &self,
        block_number_or_hash: BlockId,
    ) -> Vec<TransactionReceipt> {
        self.http_client
            .request("eth_getBlockReceipts", rpc_params![block_number_or_hash])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_get_transaction_receipt(
        &self,
        tx_hash: TxHash,
    ) -> Option<TransactionReceipt> {
        self.http_client
            .request("eth_getTransactionReceipt", rpc_params![tx_hash])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_get_tx_by_block_hash_and_index(
        &self,
        block_hash: B256,
        index: U256,
    ) -> Transaction {
        self.http_client
            .request(
                "eth_getTransactionByBlockHashAndIndex",
                rpc_params![block_hash, index],
            )
            .await
            .unwrap()
    }

    pub(crate) async fn eth_get_tx_by_block_number_and_index(
        &self,
        block_number: BlockNumberOrTag,
        index: U256,
    ) -> Transaction {
        self.http_client
            .request(
                "eth_getTransactionByBlockNumberAndIndex",
                rpc_params![block_number, index],
            )
            .await
            .unwrap()
    }

    /// params is a tuple of (fromBlock, toBlock, address, topics, blockHash)
    /// any of these params are optional
    pub(crate) async fn eth_get_logs<P>(&self, params: P) -> Vec<LogResponse>
    where
        P: serde::Serialize,
    {
        let rpc_params = rpc_params!(params);
        let eth_logs: Vec<LogResponse> = self
            .http_client
            .request("eth_getLogs", rpc_params)
            .await
            .unwrap();
        eth_logs
    }

    #[allow(clippy::extra_unused_type_parameters)]
    pub(crate) async fn ledger_get_soft_confirmation_by_number<
        DaSpec: sov_rollup_interface::da::DaSpec,
    >(
        &self,
        num: u64,
    ) -> Option<GetSoftConfirmationResponse> {
        self.http_client
            .request("ledger_getSoftConfirmationByNumber", rpc_params![num])
            .await
            .unwrap()
    }

    pub(crate) async fn ledger_get_soft_confirmation_status(
        &self,
        soft_confirmation_receipt: u64,
    ) -> Result<Option<SoftConfirmationStatus>, Box<dyn std::error::Error>> {
        self.http_client
            .request(
                "ledger_getSoftConfirmationStatus",
                rpc_params![soft_confirmation_receipt],
            )
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn ledger_get_last_scanned_l1_height(&self) -> u64 {
        self.http_client
            .request("ledger_getLastScannedL1Height", rpc_params![])
            .await
            .unwrap()
    }

    pub(crate) async fn ledger_get_sequencer_commitments_on_slot_by_number(
        &self,
        height: u64,
    ) -> anyhow::Result<Option<Vec<SequencerCommitmentResponse>>> {
        self.http_client
            .request(
                "ledger_getSequencerCommitmentsOnSlotByNumber",
                rpc_params![height],
            )
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn ledger_get_batch_proofs_by_slot_height(
        &self,
        height: u64,
    ) -> Vec<BatchProofResponse> {
        self.http_client
            .request("ledger_getBatchProofsBySlotHeight", rpc_params![height])
            .await
            .unwrap()
    }

    pub(crate) async fn ledger_get_verified_batch_proofs_by_slot_height(
        &self,
        height: u64,
    ) -> Option<Vec<VerifiedBatchProofResponse>> {
        self.http_client
            .request(
                "ledger_getVerifiedBatchProofsBySlotHeight",
                rpc_params![height],
            )
            .await
            .ok()
    }

    pub(crate) async fn ledger_get_last_verified_batch_proof(
        &self,
    ) -> Option<LastVerifiedBatchProofResponse> {
        self.http_client
            .request("ledger_getLastVerifiedBatchProof", rpc_params![])
            .await
            .ok()
    }

    pub(crate) async fn ledger_get_sequencer_commitments_on_slot_by_hash(
        &self,
        hash: [u8; 32],
    ) -> Result<Option<Vec<SequencerCommitmentResponse>>, Box<dyn std::error::Error>> {
        self.http_client
            .get_sequencer_commitments_on_slot_by_hash(HexHash(hash))
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn ledger_get_head_soft_confirmation(
        &self,
    ) -> Result<Option<SoftConfirmationResponse>, Box<dyn std::error::Error>> {
        self.http_client
            .request("ledger_getHeadSoftConfirmation", rpc_params![])
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn ledger_get_head_soft_confirmation_height(
        &self,
    ) -> Result<Option<u64>, Box<dyn std::error::Error>> {
        self.http_client
            .request("ledger_getHeadSoftConfirmationHeight", rpc_params![])
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn get_max_l2_blocks_per_l1(&self) -> u64 {
        self.http_client
            .request(
                "softConfirmationRuleEnforcer_getMaxL2BlocksPerL1",
                rpc_params![],
            )
            .await
            .unwrap()
    }

    pub(crate) async fn debug_trace_transaction(
        &self,
        tx_hash: TxHash,
        opts: Option<GethDebugTracingOptions>,
    ) -> GethTrace {
        self.http_client
            .request("debug_traceTransaction", rpc_params![tx_hash, opts])
            .await
            .unwrap()
    }

    pub(crate) async fn debug_trace_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
        opts: Option<GethDebugTracingOptions>,
    ) -> Vec<GethTrace> {
        self.http_client
            .request("debug_traceBlockByNumber", rpc_params![block_number, opts])
            .await
            .unwrap()
    }

    pub(crate) async fn debug_trace_block_by_hash(
        &self,
        block_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> Vec<GethTrace> {
        self.http_client
            .request("debug_traceBlockByHash", rpc_params![block_hash, opts])
            .await
            .unwrap()
    }

    pub(crate) async fn debug_trace_chain(
        &self,
        start_block: BlockNumberOrTag,
        end_block: BlockNumberOrTag,
        opts: Option<GethDebugTracingOptions>,
    ) -> Vec<GethTrace> {
        let mut subscription = self
            .ws_client
            .subscribe(
                "debug_subscribe",
                rpc_params!["traceChain", start_block, end_block, opts],
                "debug_unsubscribe",
            )
            .await
            .unwrap();

        let BlockNumberOrTag::Number(start_block) = start_block else {
            panic!("Only numbers for start block");
        };
        let end_block = match end_block {
            BlockNumberOrTag::Number(b) => b,
            BlockNumberOrTag::Latest => self.eth_block_number().await,
            _ => panic!("Only number and latest"),
        };
        let mut traces: Vec<Vec<GethTrace>> = vec![];
        for _ in start_block..end_block {
            let block_traces = subscription.next().await.unwrap().unwrap();
            traces.push(block_traces);
        }

        traces.into_iter().flatten().collect()
    }

    pub(crate) async fn subscribe_new_heads(&self) -> mpsc::Receiver<RichBlock> {
        let (tx, rx) = mpsc::channel();
        let mut subscription = self
            .ws_client
            .subscribe("eth_subscribe", rpc_params!["newHeads"], "eth_unsubscribe")
            .await
            .unwrap();

        tokio::spawn(async move {
            loop {
                let Some(Ok(block)) = subscription.next().await else {
                    return;
                };
                tx.send(block).unwrap();
            }
        });

        rx
    }

    pub(crate) async fn subscribe_logs(&self, filter: Filter) -> mpsc::Receiver<LogResponse> {
        let (tx, rx) = mpsc::channel();
        let mut subscription = self
            .ws_client
            .subscribe(
                "eth_subscribe",
                rpc_params!["logs", filter],
                "eth_unsubscribe",
            )
            .await
            .unwrap();

        tokio::spawn(async move {
            loop {
                let Some(Ok(log)) = subscription.next().await else {
                    return;
                };
                tx.send(log).unwrap();
            }
        });

        rx
    }

    pub(crate) async fn eth_block_number(&self) -> u64 {
        let block_number: U256 = self
            .http_client
            .request("eth_blockNumber", rpc_params![])
            .await
            .unwrap();

        block_number.saturating_to()
    }

    pub(crate) async fn citrea_sync_status(&self) -> SyncStatus {
        self.http_client
            .request("citrea_syncStatus", rpc_params![])
            .await
            .unwrap()
    }

    pub(crate) async fn batch_prover_prove(
        &self,
        l1_height: u64,
        group_commitments: Option<GroupCommitments>,
    ) {
        self.http_client
            .request(
                "batchProver_prove",
                rpc_params![l1_height, group_commitments],
            )
            .await
            .unwrap()
    }
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
// ethers version of FeeHistory doesn't accept None reward
pub struct FeeHistory {
    pub base_fee_per_gas: Vec<U256>,
    pub gas_used_ratio: Vec<f64>,
    pub oldest_block: U256,
    pub reward: Option<Vec<Vec<U256>>>,
}
