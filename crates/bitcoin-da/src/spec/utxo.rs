use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
#[cfg(feature = "native")]
use bitcoincore_rpc::json::ListUnspentResultEntry;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UTXO {
    pub tx_id: Txid,
    pub vout: u32,
    pub address: Option<Address<NetworkUnchecked>>,
    pub script_pubkey: String,
    pub amount: u64,
    pub confirmations: u32,
    pub spendable: bool,
    pub solvable: bool,
}

#[cfg(feature = "native")]
impl From<ListUnspentResultEntry> for UTXO {
    fn from(v: ListUnspentResultEntry) -> Self {
        Self {
            tx_id: v.txid,
            vout: v.vout,
            address: v.address,
            script_pubkey: v.script_pub_key.to_hex_string(),
            amount: v.amount.to_sat(),
            confirmations: v.confirmations,
            spendable: v.spendable,
            solvable: v.solvable,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListUnspentEntry {
    pub txid: Txid,
    pub vout: u64,
    pub address: String,
    pub label: Option<String>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: String,
    pub amount: f64,
    pub confirmations: u64,
    #[serde(rename = "ancestorcount")]
    pub ancestor_count: Option<u64>,
    #[serde(rename = "ancestorsize")]
    pub ancestor_size: Option<u64>,
    #[serde(rename = "ancestorfees")]
    pub ancestor_fees: Option<u64>,
    pub spendable: bool,
    pub solvable: bool,
    pub desc: String,
    pub parent_descs: Option<Vec<String>>,
    pub safe: bool,
}
