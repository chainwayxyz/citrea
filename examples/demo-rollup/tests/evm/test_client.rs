use ethereum_types::H160;
use ethers_core::abi::Address;
use ethers_core::k256::ecdsa::SigningKey;
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::{
    Block, Eip1559TransactionRequest, Transaction, TransactionRequest, TxHash,
};
use ethers_middleware::SignerMiddleware;
use ethers_providers::{Http, Middleware, PendingTransaction, Provider};
use ethers_signers::Wallet;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use reth_primitives::{BlockNumberOrTag, Bytes};
use sov_evm::{LogResponse, LogsContract, SimpleStorageContract, TestContract};

const MAX_FEE_PER_GAS: u64 = 100000001;
const GAS: u64 = 900000u64;

pub struct TestClient<T: TestContract> {
    chain_id: u64,
    pub(crate) from_addr: Address,
    contract: T,
    client: SignerMiddleware<Provider<Http>, Wallet<SigningKey>>,
    http_client: HttpClient,
}

impl<T: TestContract> TestClient<T> {
    #[allow(dead_code)]
    pub(crate) async fn new(
        chain_id: u64,
        key: Wallet<SigningKey>,
        from_addr: Address,
        contract: T,
        rpc_addr: std::net::SocketAddr,
    ) -> Self {
        let host = format!("http://localhost:{}", rpc_addr.port());

        let provider = Provider::try_from(&host).unwrap();
        let client = SignerMiddleware::new_with_provider_chain(provider, key)
            .await
            .unwrap();

        let http_client = HttpClientBuilder::default().build(host).unwrap();

        Self {
            chain_id,
            from_addr,
            contract,
            client,
            http_client,
        }
    }

    pub(crate) async fn send_publish_batch_request(&self) {
        let _: String = self
            .http_client
            .request("eth_publishBatch", rpc_params![])
            .await
            .unwrap();
    }

    pub(crate) async fn deploy_contract(
        &self,
    ) -> Result<PendingTransaction<'_, Http>, Box<dyn std::error::Error>> {
        let nonce = self.eth_get_transaction_count(self.from_addr).await;
        let req = Eip1559TransactionRequest::new()
            .from(self.from_addr)
            .chain_id(self.chain_id)
            .nonce(nonce)
            .max_priority_fee_per_gas(10u64)
            .max_fee_per_gas(MAX_FEE_PER_GAS)
            .gas(GAS)
            .data(self.contract.byte_code());

        let typed_transaction = TypedTransaction::Eip1559(req);

        let receipt_req = self
            .client
            .send_transaction(typed_transaction, None)
            .await?;

        Ok(receipt_req)
    }

    pub(crate) async fn deploy_contract_call(&self) -> Result<Bytes, Box<dyn std::error::Error>> {
        let nonce = self.eth_get_transaction_count(self.from_addr).await;
        let req = Eip1559TransactionRequest::new()
            .from(self.from_addr)
            .chain_id(self.chain_id)
            .nonce(nonce)
            .max_priority_fee_per_gas(10u64)
            .max_fee_per_gas(MAX_FEE_PER_GAS)
            .gas(GAS)
            .data(self.contract.byte_code());

        let typed_transaction = TypedTransaction::Eip1559(req);

        let receipt_req = self.eth_call(typed_transaction, None).await?;

        Ok(receipt_req)
    }

    pub(crate) async fn call_logs_contract(
        &self,
        contract_address: H160,
        message: String,
    ) -> PendingTransaction<'_, Http> {
        let contract: &LogsContract = match self.contract.as_any().downcast_ref::<LogsContract>() {
            Some(lc) => lc,
            None => panic!("Contract isn't a Logs Contract!"),
        };

        let req = Eip1559TransactionRequest::new()
            .from(self.from_addr)
            .to(contract_address)
            .chain_id(self.chain_id)
            .data(contract.publish_event(message))
            .max_priority_fee_per_gas(10u64)
            .max_fee_per_gas(MAX_FEE_PER_GAS);

        let typed_transaction = TypedTransaction::Eip1559(req);

        self.eth_send_transaction(typed_transaction).await
    }

    pub(crate) async fn set_value_unsigned(
        &self,
        contract_address: H160,
        set_arg: u32,
    ) -> PendingTransaction<'_, Http> {
        // Tx without gas_limit should estimate and include it in send_transaction endpoint
        // Tx without nonce should fetch and include it in send_transaction endpoint
        let contract: &SimpleStorageContract = self.get_simple_storage_contract();
        let req = Eip1559TransactionRequest::new()
            .from(self.from_addr)
            .to(contract_address)
            .chain_id(self.chain_id)
            .data(contract.set_call_data(set_arg))
            .max_priority_fee_per_gas(10u64)
            .max_fee_per_gas(MAX_FEE_PER_GAS);

        let typed_transaction = TypedTransaction::Eip1559(req);

        self.eth_send_transaction(typed_transaction).await
    }

    pub(crate) async fn set_value(
        &self,
        contract_address: H160,
        set_arg: u32,
        max_priority_fee_per_gas: Option<u64>,
        max_fee_per_gas: Option<u64>,
    ) -> PendingTransaction<'_, Http> {
        let nonce = self.eth_get_transaction_count(self.from_addr).await;
        let contract: &SimpleStorageContract = self.get_simple_storage_contract();

        let req = Eip1559TransactionRequest::new()
            .from(self.from_addr)
            .to(contract_address)
            .chain_id(self.chain_id)
            .nonce(nonce)
            .data(contract.set_call_data(set_arg))
            .max_priority_fee_per_gas(max_priority_fee_per_gas.unwrap_or(10u64))
            .max_fee_per_gas(max_fee_per_gas.unwrap_or(MAX_FEE_PER_GAS))
            .gas(GAS);

        let typed_transaction = TypedTransaction::Eip1559(req);

        self.client
            .send_transaction(typed_transaction, None)
            .await
            .unwrap()
    }

    pub(crate) async fn set_value_call(
        &self,
        contract_address: H160,
        set_arg: u32,
    ) -> Result<Bytes, Box<dyn std::error::Error>> {
        let nonce = self.eth_get_transaction_count(self.from_addr).await;

        let contract: &SimpleStorageContract = self.get_simple_storage_contract();
        // Any type of transaction can be used for eth_call
        let req = TransactionRequest::new()
            .from(self.from_addr)
            .to(contract_address)
            .chain_id(self.chain_id)
            .nonce(nonce)
            .data(contract.set_call_data(set_arg))
            .gas_price(10u64);

        let typed_transaction = TypedTransaction::Legacy(req.clone());

        // Estimate gas on rpc
        let gas = self
            .eth_estimate_gas(typed_transaction, Some("latest".to_owned()))
            .await;

        // Call with the estimated gas
        let req = req.gas(gas);
        let typed_transaction = TypedTransaction::Legacy(req);

        let response = self
            .eth_call(typed_transaction, Some("latest".to_owned()))
            .await?;

        Ok(response)
    }

    pub(crate) async fn failing_call(
        &self,
        contract_address: H160,
    ) -> Result<Bytes, Box<dyn std::error::Error>> {
        let nonce = self.eth_get_transaction_count(self.from_addr).await;

        let contract: &SimpleStorageContract = self.get_simple_storage_contract();

        // Any type of transaction can be used for eth_call
        let req = Eip1559TransactionRequest::new()
            .from(self.from_addr)
            .to(contract_address)
            .chain_id(self.chain_id)
            .nonce(nonce)
            .data(contract.failing_function_call_data())
            .max_priority_fee_per_gas(10u64)
            .max_fee_per_gas(MAX_FEE_PER_GAS)
            .gas(GAS);

        let typed_transaction = TypedTransaction::Eip1559(req);

        self.eth_call(typed_transaction, Some("latest".to_owned()))
            .await
    }

    pub(crate) async fn query_contract(
        &self,
        contract_address: H160,
    ) -> Result<ethereum_types::U256, Box<dyn std::error::Error>> {
        let nonce = self.eth_get_transaction_count(self.from_addr).await;

        let contract: &SimpleStorageContract = self.get_simple_storage_contract();

        let req = Eip1559TransactionRequest::new()
            .from(self.from_addr)
            .to(contract_address)
            .chain_id(self.chain_id)
            .nonce(nonce)
            .data(contract.get_call_data())
            .gas(GAS);

        let typed_transaction = TypedTransaction::Eip1559(req);

        let response = self.client.call(&typed_transaction, None).await?;

        let resp_array: [u8; 32] = response.to_vec().try_into().unwrap();
        Ok(ethereum_types::U256::from(resp_array))
    }

    pub(crate) async fn eth_accounts(&self) -> Vec<Address> {
        self.http_client
            .request("eth_accounts", rpc_params![])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_send_transaction(
        &self,
        tx: TypedTransaction,
    ) -> PendingTransaction<'_, Http> {
        self.client
            .provider()
            .send_transaction(tx, None)
            .await
            .unwrap()
    }

    pub(crate) async fn eth_chain_id(&self) -> u64 {
        let chain_id: ethereum_types::U64 = self
            .http_client
            .request("eth_chainId", rpc_params![])
            .await
            .unwrap();

        chain_id.as_u64()
    }

    pub(crate) async fn eth_get_balance(&self, address: Address) -> ethereum_types::U256 {
        self.http_client
            .request("eth_getBalance", rpc_params![address, "latest"])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_get_storage_at(
        &self,
        address: Address,
        index: ethereum_types::U256,
    ) -> ethereum_types::U256 {
        self.http_client
            .request("eth_getStorageAt", rpc_params![address, index, "latest"])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_get_code(&self, address: Address) -> Bytes {
        self.http_client
            .request("eth_getCode", rpc_params![address, "latest"])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_get_transaction_count(&self, address: Address) -> u64 {
        let count: ethereum_types::U64 = self
            .http_client
            .request("eth_getTransactionCount", rpc_params![address, "latest"])
            .await
            .unwrap();

        count.as_u64()
    }

    pub(crate) async fn eth_gas_price(&self) -> ethereum_types::U256 {
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
        block_number: Option<String>,
    ) -> Block<TxHash> {
        self.http_client
            .request("eth_getBlockByNumber", rpc_params![block_number, false])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_get_block_by_number_with_detail(
        &self,
        block_number: Option<String>,
    ) -> Block<Transaction> {
        self.http_client
            .request("eth_getBlockByNumber", rpc_params![block_number, true])
            .await
            .unwrap()
    }

    pub(crate) async fn eth_call(
        &self,
        tx: TypedTransaction,
        block_number: Option<String>,
    ) -> Result<Bytes, Box<dyn std::error::Error>> {
        self.http_client
            .request("eth_call", rpc_params![tx, block_number])
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn eth_estimate_gas(
        &self,
        tx: TypedTransaction,
        block_number: Option<String>,
    ) -> u64 {
        let gas: ethereum_types::U64 = self
            .http_client
            .request("eth_estimateGas", rpc_params![tx, block_number])
            .await
            .unwrap();

        gas.as_u64()
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

    pub(crate) fn get_simple_storage_contract(&self) -> &SimpleStorageContract {
        let contract: &SimpleStorageContract = match self
            .contract
            .as_any()
            .downcast_ref::<SimpleStorageContract>()
        {
            Some(ssc) => ssc,
            None => panic!("Contract isn't a Simple Storage Contract!"),
        };
        contract
    }
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
// ethers version of FeeHistory doesn't accept None reward
pub struct FeeHistory {
    pub base_fee_per_gas: Vec<ethers::types::U256>,
    pub gas_used_ratio: Vec<f64>,
    pub oldest_block: ethers::types::U256,
    pub reward: Option<Vec<Vec<ethers::types::U256>>>,
}
