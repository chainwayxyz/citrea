use core::fmt::Display;
use core::str::FromStr;

use anyhow::anyhow;
use async_recursion::async_recursion;
use bitcoin::block::{Header, Version};
use bitcoin::hash_types::TxMerkleNode;
use bitcoin::{Address, BlockHash, CompactTarget, Network};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{json, to_value};

use crate::helpers::parsers::parse_hex_transaction;
use crate::spec::block::BitcoinBlock;
use crate::spec::header::HeaderWrapper;
use crate::spec::transaction::Transaction;
use crate::spec::utxo::UTXO;

// RPCError is a struct that represents an error returned by the Bitcoin RPC
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RPCError {
    pub code: i32,
    pub message: String,
}
impl Display for RPCError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "RPCError {}: {}", self.code, self.message)
    }
}

// Response is a struct that represents a response returned by the Bitcoin RPC
// It is generic over the type of the result field, which is usually a String in Bitcoin Core
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
struct Response<R = String> {
    pub result: Option<R>,
    pub error: Option<RPCError>,
    pub id: String,
}

// BitcoinNode is a struct that represents a connection to a Bitcoin RPC node
#[derive(Debug, Clone)]
pub struct BitcoinNode {
    url: String,
    client: reqwest::Client,
    network: Network,
}
impl BitcoinNode {
    pub fn new(url: String, username: String, password: String, network: Network) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!(
                "Basic {}",
                base64::encode(format!("{}:{}", username, password))
            )
            .parse()
            .expect("Failed to parse auth header!"),
        );
        headers.insert(
            "Content-Type",
            "application/json"
                .parse()
                .expect("Failed to parse content type header!"),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("Failed to build client!");

        Self {
            url,
            client,
            network,
        }
    }

    // TODO: add max retries
    #[async_recursion]
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<T, anyhow::Error> {
        let response = self
            .client
            .post(&self.url)
            .json(&json!({
                "jsonrpc": "1.0",
                "id": method,
                "method": method,
                "params": params
            }))
            .send()
            .await;

        // sometimes requests to bitcoind are dropped without a reason
        // so impl. recursive retry
        // TODO: add max retries
        if let Err(error) = response {
            // TODO: maybe remove is_request() check?
            if error.is_connect() || error.is_timeout() || error.is_request() {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                return self.call(method, params).await;
            }
            return Err(anyhow!(error));
        }

        let response = response.unwrap().json::<Response<T>>().await?;

        if let Some(error) = response.error {
            return Err(anyhow!(error));
        }

        Ok(response.result.unwrap())
    }

    // get_block_count returns the current block height
    pub async fn get_block_count(&self) -> Result<u64, anyhow::Error> {
        self.call::<u64>("getblockcount", vec![]).await
    }

    // get_block_hash returns the block hash of the block at the given height
    pub async fn get_block_hash(&self, height: u64) -> Result<String, anyhow::Error> {
        self.call::<String>("getblockhash", vec![to_value(height)?])
            .await
    }

    // get_block returns the block at the given hash
    pub async fn get_block(&self, hash: String) -> Result<BitcoinBlock, anyhow::Error> {
        let result = self
            .call::<Box<RawValue>>("getblock", vec![to_value(hash.clone())?, to_value(3)?])
            .await?
            .to_string();

        let full_block: serde_json::Value = serde_json::from_str(&result)?;

        let header: Header = Header {
            bits: CompactTarget::from_consensus(u32::from_str_radix(
                full_block["bits"].as_str().unwrap(),
                16,
            )?),
            merkle_root: TxMerkleNode::from_str(full_block["merkleroot"].as_str().unwrap())?,
            nonce: full_block["nonce"].as_u64().unwrap() as u32,
            prev_blockhash: BlockHash::from_str(full_block["previousblockhash"].as_str().unwrap())?,
            time: full_block["time"].as_u64().unwrap() as u32,
            version: Version::from_consensus(full_block["version"].as_u64().unwrap() as i32),
        };

        let txdata = full_block["tx"].as_array().unwrap();

        let txs: Vec<Transaction> = txdata
            .iter()
            .map(|tx| {
                let tx_hex = tx["hex"].as_str().unwrap();

                parse_hex_transaction(tx_hex).unwrap() // hex from rpc cannot be invalid
            })
            .collect();

        let height = full_block["height"].as_u64().unwrap();

        Ok(BitcoinBlock {
            header: HeaderWrapper::new(header, txs.len() as u32, height),
            txdata: txs,
        })
    }

    // get_utxos returns all unspent transaction outputs for the wallets of bitcoind
    pub async fn get_utxos(&self) -> Result<Vec<UTXO>, anyhow::Error> {
        let utxos = self
            .call::<Vec<UTXO>>("listunspent", vec![to_value(0)?, to_value(9999999)?])
            .await?;

        if utxos.is_empty() {
            return Err(anyhow!("No UTXOs found"));
        }

        Ok(utxos)
    }

    // get_change_address returns a change address for the wallet of bitcoind
    async fn get_change_address(&self) -> Result<Address, anyhow::Error> {
        let address_string = self.call::<String>("getrawchangeaddress", vec![]).await?;
        Ok(Address::from_str(&address_string)?.require_network(self.network)?)
    }

    pub async fn get_change_addresses(&self) -> Result<[Address; 2], anyhow::Error> {
        let change_address = self.get_change_address().await?;
        let change_address_2 = self.get_change_address().await?;

        Ok([change_address, change_address_2])
    }

    // estimate_smart_fee estimates the fee to confirm a transaction in the next block
    pub async fn estimate_smart_fee(&self) -> Result<f64, anyhow::Error> {
        let result = self
            .call::<Box<RawValue>>("estimatesmartfee", vec![to_value(1)?])
            .await?
            .to_string();

        let result_map: serde_json::Value = serde_json::from_str(&result)?;

        // Issue: https://github.com/chainwayxyz/bitcoin-da/issues/3
        let btc_vkb = result_map
            .get("feerate")
            .unwrap_or(&serde_json::Value::from_str("0.00001").unwrap())
            .as_f64()
            .unwrap();

        // convert to sat/vB and round up
        Ok((btc_vkb * 100_000_000.0 / 1000.0).ceil())
    }

    // sign_raw_transaction_with_wallet signs a raw transaction with the wallet of bitcoind
    pub async fn sign_raw_transaction_with_wallet(
        &self,
        tx: String,
    ) -> Result<String, anyhow::Error> {
        let result = self
            .call::<Box<RawValue>>("signrawtransactionwithwallet", vec![to_value(tx)?])
            .await?
            .to_string();

        let signed_tx: serde_json::Value = serde_json::from_str(&result)?;

        Ok(signed_tx["hex"].as_str().unwrap().to_string())
    }

    // send_raw_transaction sends a raw transaction to the network
    pub async fn send_raw_transaction(&self, tx: String) -> Result<String, anyhow::Error> {
        self.call::<String>("sendrawtransaction", vec![to_value(tx)?])
            .await
    }

    pub async fn list_wallets(&self) -> Result<Vec<String>, anyhow::Error> {
        self.call::<Vec<String>>("listwallets", vec![]).await
    }

    #[cfg(test)]
    pub async fn generate_to_address(
        &self,
        address: Address,
        blocks: u32,
    ) -> Result<Vec<BlockHash>, anyhow::Error> {
        if self.network == Network::Regtest {
            self.call::<Vec<BlockHash>>(
                "generatetoaddress",
                vec![to_value(blocks)?, to_value(address.to_string())?],
            )
            .await
        } else {
            Err(anyhow!("Cannot generate blocks on non-regtest network"))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::BitcoinNode;

    fn get_bitcoin_node() -> BitcoinNode {
        BitcoinNode::new(
            "http://localhost:38332".to_string(),
            "chainway".to_string(),
            "topsecret".to_string(),
            bitcoin::Network::Regtest,
        )
    }

    #[tokio::test]
    async fn get_utxos() {
        let node = get_bitcoin_node();

        let utxos = node.get_utxos().await.unwrap();

        utxos.iter().for_each(|utxo| {
            println!("address: {}, amount: {}", utxo.address, utxo.amount);
        });
    }

    #[tokio::test]
    async fn list_wallets() {
        let node = get_bitcoin_node();

        let wallets = node.list_wallets().await.unwrap();

        wallets.iter().for_each(|wallet| {
            println!("wallet: {}", wallet);
        });
    }
}
