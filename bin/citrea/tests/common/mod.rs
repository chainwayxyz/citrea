#![allow(dead_code)]
use std::net::SocketAddr;
use std::str::FromStr;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy_primitives::Address;

use crate::common::client::TestClient;
pub use crate::common::constants::*;

pub mod client;
pub mod constants;
pub mod helpers;

#[allow(clippy::borrowed_box)]
pub async fn make_test_client(rpc_address: SocketAddr) -> anyhow::Result<Box<TestClient>> {
    let chain_id: u64 = 5655;
    let key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        .parse::<PrivateKeySigner>()
        .unwrap()
        .with_chain_id(Some(chain_id));

    let from_addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    Ok(Box::new(
        TestClient::new(chain_id, key, from_addr, rpc_address).await?,
    ))
}
