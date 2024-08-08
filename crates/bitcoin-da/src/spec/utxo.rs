use bitcoin::Txid;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UTXO {
    pub tx_id: Txid,
    pub vout: u32,
    pub address: String,
    pub script_pubkey: String,
    pub amount: u64,
    pub confirmations: u64,
    pub spendable: bool,
    pub solvable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListUnspentEntry {
    pub txid: String,
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

impl From<ListUnspentEntry> for UTXO {
    fn from(entry: ListUnspentEntry) -> UTXO {
        UTXO {
            tx_id: entry.txid.parse().unwrap(),
            vout: entry.vout as u32,
            address: entry.address,
            script_pubkey: entry.script_pub_key,
            amount: btc_to_satoshi(entry.amount),
            confirmations: entry.confirmations,
            spendable: entry.spendable,
            solvable: entry.solvable,
        }
    }
}

pub fn btc_to_satoshi(btc: f64) -> u64 {
    (btc * 100_000_000.0) as u64
}
