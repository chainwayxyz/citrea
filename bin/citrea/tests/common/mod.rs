#![allow(dead_code)]
use std::net::SocketAddr;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;

use crate::common::client::TestClient;
pub use crate::common::constants::*;

pub mod client;
pub mod constants;
pub mod helpers;

const DEFAULT_FUNDED_TEST_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[allow(clippy::borrowed_box)]
pub async fn make_test_client(rpc_address: SocketAddr) -> anyhow::Result<Box<TestClient>> {
    make_test_client_from_private_key(rpc_address, DEFAULT_FUNDED_TEST_PRIVATE_KEY).await
}

#[allow(clippy::borrowed_box)]
pub async fn make_test_client_from_private_key(
    rpc_address: SocketAddr,
    private_key: &str,
) -> anyhow::Result<Box<TestClient>> {
    let key = private_key
        .parse::<PrivateKeySigner>()
        .unwrap()
        .with_chain_id(Some(DEFAULT_TEST_CHAIN_ID));
    let from_addr = key.address();

    Ok(Box::new(
        TestClient::new(DEFAULT_TEST_CHAIN_ID, key, from_addr, rpc_address).await?,
    ))
}
